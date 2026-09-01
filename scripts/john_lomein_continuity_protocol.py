#!/usr/bin/env python3
"""Pure verification protocol for protected continuity writes.

This module is intentionally credential-free.  It knows how to normalize and
verify a signed continuity effect using an Ed25519 *public* key, but it does
not load private keys, sign effects, append to the continuity ledger, or
authenticate the upstream event described by ``source``.  A future protected
source adapter owns that last responsibility; this protocol only proves that
the configured key signed the bounded, cross-bound metadata.

There are three deliberately different verification APIs:

``verify_for_new_admission``
    admits only a current envelope from an active key while the importer is
    explicitly enabled;
``verify_for_replay``
    re-verifies an exact envelope digest already pinned by durable importer
    state, including after expiry or key rotation; and
``verify_historical_envelope``
    verifies audit history for active or retired keys without claiming that it
    may be newly admitted.

Retirement stops new authority without invalidating exact history.  Revocation
is deliberately stronger: public history, replay, and admission APIs all fail
closed until an operator performs an explicit forensic remediation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import john_lomein_continuity as continuity


CONFIG_SCHEMA = "john-lomein.continuity-import-config.v1"
KEY_POLICY_SCHEMA = "john-lomein.continuity-key-policy.v1"
ENVELOPE_SCHEMA = "john-lomein.continuity-signed-envelope.v1"
EFFECT_SCHEMA = "john-lomein.continuity-effect.v1"
SOURCE_COMMITMENT_SCHEMA = "john-lomein.continuity-source-commitment.v1"
VERIFICATION_SCHEMA = "john-lomein.continuity-verification.v1"
ERROR_SCHEMA = "john-lomein.continuity-protocol-error.v1"

SIGNATURE_ALGORITHM = "Ed25519"
COMMITMENT_ALGORITHM = "SHA-256"
SIGNING_DOMAIN = b"JOHN-LOMEIN-CONTINUITY-SIGNED-ENVELOPE-V1\x00"
POLICY_DOMAIN = b"JOHN-LOMEIN-CONTINUITY-KEY-POLICY-V1\x00"
SOURCE_COMMITMENT_DOMAIN = b"JOHN-LOMEIN-CONTINUITY-SOURCE-COMMITMENT-V1\x00"
SALTED_SOURCE_COMMITMENT_DOMAIN = (
    b"JOHN-LOMEIN-CONTINUITY-SALTED-SOURCE-V1\x00"
)
ENTRY_ID_DOMAIN = b"JOHN-LOMEIN-CONTINUITY-ENTRY-ID-V1\x00"
ENVELOPE_DIGEST_DOMAIN = b"JOHN-LOMEIN-CONTINUITY-ENVELOPE-DIGEST-V1\x00"

MAX_CONFIG_BYTES = 64 * 1024
# A conservative parser ceiling leaves at least half of the existing 8 KiB
# continuity line budget to the future importer wrapper.  Importer integration
# must still prove its exact final v2 record at the worst legal envelope size.
MAX_LEDGER_LINE_BYTES = continuity.MAX_LINE_BYTES
MAX_ENVELOPE_BYTES = 4 * 1024
MAX_KEYS = 16
MAX_JSON_DEPTH = 24
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 900
MAX_CLOCK_SKEW_SECONDS = 30

KEY_STATES = ("active", "retired", "revoked")
OPERATIONS = ("put", "suppress")
PRIVACY_ORDER = {"private": 0, "public": 1}
ROLE_ORDER = continuity.ROLE_ORDER
OWNER_KINDS = frozenset({"user_correction", "user_preference"})
EXTERNAL_KINDS = frozenset({"verified_outcome"})
SUPPRESSION_REASONS = frozenset(
    {"owner_request", "privacy_request", "superseded", "expired"}
)
COMMITMENT_KIND_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")

HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
WRITE_ID_RE = re.compile(r"^jlcw-[0-9a-f]{32}$")
ENTRY_ID_RE = re.compile(r"^jlce-[0-9a-f]{24}$")
LEDGER_ID_RE = re.compile(r"^jlcl-[0-9a-f]{24}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,191}$")
REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")

# RFC 8032 §5.1 parameters.  cryptography verifies the group equation, but
# some backend versions accept the identity public key/signature pair.  The
# protocol therefore performs strict canonical decoding and subgroup checks
# before handing a signature to the dependency.
_ED25519_FIELD_PRIME = 2**255 - 19
_ED25519_D = (
    -121665
    * pow(121666, _ED25519_FIELD_PRIME - 2, _ED25519_FIELD_PRIME)
) % _ED25519_FIELD_PRIME
_ED25519_SQRT_M1 = pow(
    2,
    (_ED25519_FIELD_PRIME - 1) // 4,
    _ED25519_FIELD_PRIME,
)
_ED25519_SUBGROUP_ORDER = (
    2**252 + 27742317777372353535851937790883648493
)
_ED25519_IDENTITY = (0, 1, 1, 0)

_PUBLIC_MESSAGES = {
    "malformed_json": "signed continuity JSON is malformed",
    "duplicate_field": "signed continuity JSON contains duplicate fields",
    "noncanonical_json": "signed continuity JSON is not canonical",
    "size_exceeded": "signed continuity input exceeds its size limit",
    "schema_invalid": "signed continuity schema is invalid",
    "unsupported_schema": "signed continuity schema is unsupported",
    "unsupported_algorithm": "signed continuity algorithm is unsupported",
    "importer_disabled": "signed continuity admission is disabled",
    "key_unknown": "signed continuity key is not configured",
    "key_material_invalid": "signed continuity public key is invalid",
    "key_fingerprint_mismatch": "signed continuity key fingerprint differs",
    "signature_invalid": "signed continuity signature is invalid",
    "policy_mismatch": "signed continuity policy binding differs",
    "instance_mismatch": "signed continuity instance binding differs",
    "ledger_mismatch": "signed continuity ledger binding differs",
    "authority_mismatch": "signed continuity authority binding differs",
    "operation_denied": "signed continuity operation is not authorized",
    "kind_denied": "signed continuity record kind is not authorized",
    "scope_denied": "signed continuity scope is not authorized",
    "source_commitment_invalid": "signed continuity source commitment differs",
    "time_invalid": "signed continuity time binding is invalid",
    "not_yet_valid": "signed continuity envelope is not yet valid",
    "expired": "signed continuity envelope has expired",
    "key_retired": "signed continuity key is retired",
    "key_revoked": "signed continuity key is revoked",
    "replay_digest_mismatch": "signed continuity replay binding differs",
}


class ContinuityProtocolError(RuntimeError):
    """Fail-closed protocol error whose text never includes hostile input."""

    def __init__(self, code: str):
        if type(code) is not str or code not in _PUBLIC_MESSAGES:
            code = "schema_invalid"
        self.code = code
        super().__init__(_PUBLIC_MESSAGES[code])


class _DuplicateField(ValueError):
    pass


class _NoncanonicalNumber(ValueError):
    pass


def _error(code: str) -> ContinuityProtocolError:
    return ContinuityProtocolError(code)


def _public_boundary(default_code: str = "schema_invalid"):
    """Convert every malformed caller object into one redacted protocol code."""

    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            failure_code: str | None = None
            try:
                return function(*args, **kwargs)
            except ContinuityProtocolError as exc:
                failure_code = exc.code
            except Exception:
                failure_code = default_code
            # Raise outside the handler so hostile exceptions are neither an
            # explicit cause nor a printable implicit traceback context.
            raise _error(failure_code) from None

        return wrapped

    return decorate


def public_error(error: BaseException) -> dict[str, Any]:
    """Return a bounded, input-free public projection of a protocol failure."""

    code = "schema_invalid"
    if type(error) is ContinuityProtocolError:
        candidate = vars(error).get("code")
        if type(candidate) is str and candidate in _PUBLIC_MESSAGES:
            code = candidate
    return {
        "schema_version": ERROR_SCHEMA,
        "ok": False,
        "error_code": code,
        "message": _PUBLIC_MESSAGES[code],
    }


def _validate_canonical_value(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise _error("schema_invalid")
    if value is None or type(value) in {str, bool}:
        return
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            raise _error("schema_invalid")
        return
    if type(value) is float:
        raise _error("noncanonical_json")
    if type(value) is list:
        for item in value:
            _validate_canonical_value(item, depth=depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise _error("schema_invalid")
            _validate_canonical_value(item, depth=depth + 1)
        return
    raise _error("schema_invalid")


@_public_boundary()
def canonical_json(value: Any) -> bytes:
    """Encode the sole signing representation; floats are never permitted."""

    _validate_canonical_value(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_domain(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + canonical_json(value)).hexdigest()


def _ed25519_add(
    first: tuple[int, int, int, int],
    second: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    """Complete extended-coordinate addition from RFC 8032 §5.1.4."""

    prime = _ED25519_FIELD_PRIME
    x1, y1, z1, t1 = first
    x2, y2, z2, t2 = second
    a = ((y1 - x1) * (y2 - x2)) % prime
    b = ((y1 + x1) * (y2 + x2)) % prime
    c = (2 * _ED25519_D * t1 * t2) % prime
    d = (2 * z1 * z2) % prime
    e = (b - a) % prime
    f = (d - c) % prime
    g = (d + c) % prime
    h = (b + a) % prime
    return (
        (e * f) % prime,
        (g * h) % prime,
        (f * g) % prime,
        (e * h) % prime,
    )


def _ed25519_scalar_multiply(
    scalar: int,
    point: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    result = _ED25519_IDENTITY
    addend = point
    remaining = scalar
    while remaining:
        if remaining & 1:
            result = _ed25519_add(result, addend)
        addend = _ed25519_add(addend, addend)
        remaining >>= 1
    return result


def _ed25519_is_identity(point: tuple[int, int, int, int]) -> bool:
    x, y, z, _ = point
    prime = _ED25519_FIELD_PRIME
    return x % prime == 0 and (y - z) % prime == 0 and z % prime != 0


def _ed25519_decode_point(
    encoded: bytes,
    *,
    error_code: str,
) -> tuple[int, int, int, int]:
    """Strictly decode one canonical compressed Edwards25519 point."""

    if type(encoded) is not bytes or len(encoded) != 32:
        raise _error(error_code)
    encoded_integer = int.from_bytes(encoded, "little")
    x_sign = encoded_integer >> 255
    y = encoded_integer & ((1 << 255) - 1)
    prime = _ED25519_FIELD_PRIME
    if y >= prime:
        raise _error(error_code)
    y_squared = y * y % prime
    numerator = (y_squared - 1) % prime
    denominator = (_ED25519_D * y_squared + 1) % prime
    if denominator == 0:
        raise _error(error_code)
    x_squared = numerator * pow(denominator, prime - 2, prime) % prime
    x = pow(x_squared, (prime + 3) // 8, prime)
    if (x * x - x_squared) % prime != 0:
        x = x * _ED25519_SQRT_M1 % prime
    if (x * x - x_squared) % prime != 0:
        raise _error(error_code)
    if x == 0 and x_sign == 1:
        raise _error(error_code)
    if (x & 1) != x_sign:
        x = prime - x
    # The equation check is redundant with recovery, but makes the accepted
    # point contract explicit and protects future arithmetic refactors.
    if (
        (-x * x + y_squared - 1 - _ED25519_D * x * x * y_squared)
        % prime
        != 0
    ):
        raise _error(error_code)
    return (x, y, 1, x * y % prime)


def _validate_ed25519_prime_order_point(
    encoded: bytes,
    *,
    error_code: str,
) -> None:
    point = _ed25519_decode_point(encoded, error_code=error_code)
    if _ed25519_is_identity(point) or not _ed25519_is_identity(
        _ed25519_scalar_multiply(_ED25519_SUBGROUP_ORDER, point)
    ):
        # This rejects identity, low-order, and mixed-order points.  A valid
        # Ed25519 public key or R is a non-identity member of the prime-order
        # subgroup generated by B.
        raise _error(error_code)


def _validate_ed25519_signature_encoding(signature: bytes) -> None:
    if type(signature) is not bytes or len(signature) != 64:
        raise _error("signature_invalid")
    _validate_ed25519_prime_order_point(
        signature[:32],
        error_code="signature_invalid",
    )
    if int.from_bytes(signature[32:], "little") >= _ED25519_SUBGROUP_ORDER:
        raise _error("signature_invalid")


def _pairs_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateField
        result[key] = value
    return result


def _reject_float(_: str) -> Any:
    raise _NoncanonicalNumber


def _parse_json(raw: bytes, *, maximum_bytes: int) -> Any:
    if type(raw) is not bytes:
        raise _error("malformed_json")
    if not raw or len(raw) > maximum_bytes:
        raise _error("size_exceeded" if raw else "malformed_json")
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_pairs_object,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except _DuplicateField:
        raise _error("duplicate_field") from None
    except _NoncanonicalNumber:
        raise _error("noncanonical_json") from None
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise _error("malformed_json") from None


def _mapping(value: Any) -> Mapping[str, Any]:
    # Exact dicts keep schema reads inert.  An arbitrary Mapping can execute
    # attacker-controlled __iter__/__getitem__ code while being normalized.
    if type(value) is not dict:
        raise _error("schema_invalid")
    return value


def _strict_keys(value: Mapping[str, Any], required: set[str]) -> None:
    # Reject active key objects before hashing them into a set.
    if any(type(key) is not str for key in value) or set(value) != required:
        raise _error("schema_invalid")


def _text(value: Any, pattern: re.Pattern[str] = TOKEN_RE) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise _error("schema_invalid")
    return value


def _digest(value: Any) -> str:
    return _text(value, HEX_SHA256_RE)


def _integer(
    value: Any,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _error("schema_invalid")
    return value


def _utc(value: Any) -> datetime:
    if type(value) is not str:
        raise _error("time_invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise _error("time_invalid") from None
    return parsed.replace(tzinfo=timezone.utc)


def _utc_text(value: datetime) -> str:
    if type(value) is not datetime:
        raise _error("time_invalid")
    try:
        if value.tzinfo is None or value.utcoffset() is None:
            raise _error("time_invalid")
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ContinuityProtocolError:
        raise
    except Exception:
        raise _error("time_invalid") from None


def _now(value: datetime | None) -> datetime:
    selected = datetime.now(timezone.utc) if value is None else value
    if type(selected) is not datetime:
        raise _error("time_invalid")
    try:
        if selected.tzinfo is None or selected.utcoffset() is None:
            raise _error("time_invalid")
        return selected.astimezone(timezone.utc)
    except ContinuityProtocolError:
        raise
    except Exception:
        raise _error("time_invalid") from None


def _ordered_unique(
    raw: Any,
    *,
    allowed: set[str] | frozenset[str],
    order: Mapping[str, int],
) -> list[str]:
    if (
        type(raw) is not list
        or not raw
        or any(type(item) is not str or item not in allowed for item in raw)
    ):
        raise _error("schema_invalid")
    normalized = sorted(set(raw), key=order.__getitem__)
    if len(normalized) != len(raw):
        raise _error("schema_invalid")
    return normalized


def _normalize_authority(value: Any) -> dict[str, str]:
    authority = _mapping(value)
    _strict_keys(
        authority,
        {"class", "source_kind", "source_trust", "source_actor"},
    )
    authority_class = authority.get("class")
    source_kind = authority.get("source_kind")
    source_trust = authority.get("source_trust")
    if (
        type(authority_class) is not str
        or type(source_kind) is not str
        or type(source_trust) is not str
    ):
        raise _error("authority_mismatch")
    if authority_class == "owner":
        if source_kind != "owner" or source_trust != "owner_asserted":
            raise _error("authority_mismatch")
    elif authority_class == "external_observer":
        if (
            source_kind not in continuity.EXTERNAL_SOURCES
            or source_trust != "externally_verified"
        ):
            raise _error("authority_mismatch")
    else:
        raise _error("authority_mismatch")
    return {
        "class": authority_class,
        "source_kind": str(source_kind),
        "source_trust": str(source_trust),
        "source_actor": _text(authority.get("source_actor")),
    }


def _normalize_permissions(
    value: Any,
    *,
    authority: Mapping[str, str],
) -> dict[str, Any]:
    permissions = _mapping(value)
    _strict_keys(
        permissions,
        {
            "operations",
            "entry_kinds",
            "source_commitment_kinds",
            "privacy",
            "visible_to_roles",
        },
    )
    operations = _ordered_unique(
        permissions.get("operations"),
        allowed=set(OPERATIONS),
        order={item: index for index, item in enumerate(OPERATIONS)},
    )
    permitted_intrinsic = (
        OWNER_KINDS
        if authority["class"] == "owner"
        else EXTERNAL_KINDS
    )
    raw_entry_kinds = permissions.get("entry_kinds")
    if type(raw_entry_kinds) is not list or any(
        type(item) is not str or item not in permitted_intrinsic
        for item in raw_entry_kinds
    ):
        raise _error("schema_invalid")
    entry_order = {
        item: index
        for index, item in enumerate(
            ["user_correction", "user_preference", "verified_outcome"]
        )
    }
    entry_kinds = sorted(set(raw_entry_kinds), key=entry_order.__getitem__)
    if len(entry_kinds) != len(raw_entry_kinds):
        raise _error("schema_invalid")
    if ("put" in operations) != bool(entry_kinds):
        # A suppress-only key needs no latent put grant.  Conversely a key
        # that can put must name at least one exact semantic kind.
        raise _error("schema_invalid")
    if authority["class"] == "external_observer" and "suppress" in operations:
        raise _error("operation_denied")
    raw_commitment_kinds = permissions.get("source_commitment_kinds")
    if (
        type(raw_commitment_kinds) is not list
        or not raw_commitment_kinds
        or len(raw_commitment_kinds) > 8
        or any(
            type(item) is not str
            or COMMITMENT_KIND_RE.fullmatch(item) is None
            for item in raw_commitment_kinds
        )
    ):
        raise _error("schema_invalid")
    commitment_kinds = sorted(set(raw_commitment_kinds))
    if len(commitment_kinds) != len(raw_commitment_kinds):
        raise _error("schema_invalid")
    privacy = _ordered_unique(
        permissions.get("privacy"),
        allowed=set(PRIVACY_ORDER),
        order=PRIVACY_ORDER,
    )
    roles = _ordered_unique(
        permissions.get("visible_to_roles"),
        allowed=set(ROLE_ORDER),
        order=ROLE_ORDER,
    )
    return {
        "operations": operations,
        "entry_kinds": entry_kinds,
        "source_commitment_kinds": commitment_kinds,
        "privacy": privacy,
        "visible_to_roles": roles,
    }


def normalize_key_policy(value: Any) -> dict[str, Any]:
    policy = _mapping(value)
    _strict_keys(
        policy,
        {
            "schema_version",
            "policy_id",
            "key_id",
            "algorithm",
            "public_key_sha256",
            "state",
            "valid_from",
            "valid_until",
            "authority",
            "permissions",
        },
    )
    if (
        type(policy.get("schema_version")) is not str
        or policy.get("schema_version") != KEY_POLICY_SCHEMA
    ):
        raise _error("unsupported_schema")
    if (
        type(policy.get("algorithm")) is not str
        or policy.get("algorithm") != SIGNATURE_ALGORITHM
    ):
        raise _error("unsupported_algorithm")
    state = policy.get("state")
    if type(state) is not str or state not in KEY_STATES:
        raise _error("schema_invalid")
    authority = _normalize_authority(policy.get("authority"))
    permissions = _normalize_permissions(
        policy.get("permissions"),
        authority=authority,
    )
    valid_from = _utc(policy.get("valid_from"))
    valid_until = _utc(policy.get("valid_until"))
    if valid_until <= valid_from:
        raise _error("time_invalid")
    return {
        "schema_version": KEY_POLICY_SCHEMA,
        "policy_id": _text(policy.get("policy_id")),
        "key_id": _text(policy.get("key_id")),
        "algorithm": SIGNATURE_ALGORITHM,
        "public_key_sha256": _digest(policy.get("public_key_sha256")),
        "state": str(state),
        "valid_from": _utc_text(valid_from),
        "valid_until": _utc_text(valid_until),
        "authority": authority,
        "permissions": permissions,
    }


def _policy_authorization_projection(
    normalized_policy: Mapping[str, Any],
) -> dict[str, Any]:
    # ``state`` is a rotation control, not part of the immutable grant.  A
    # transition active -> retired/revoked must not break historical binding.
    return {
        key: normalized_policy[key]
        for key in (
            "schema_version",
            "policy_id",
            "key_id",
            "algorithm",
            "public_key_sha256",
            "valid_from",
            "valid_until",
            "authority",
            "permissions",
        )
    }


def policy_authorization_sha256(value: Any) -> str:
    policy = normalize_key_policy(value)
    return _sha256_domain(
        POLICY_DOMAIN,
        _policy_authorization_projection(policy),
    )


def normalize_config(value: Any) -> dict[str, Any]:
    config = _mapping(value)
    _strict_keys(
        config,
        {
            "schema_version",
            "enabled",
            "instance_id",
            "repository",
            "ledger_id",
            "maximum_ttl_seconds",
            "maximum_clock_skew_seconds",
            "key_policies",
        },
    )
    if (
        type(config.get("schema_version")) is not str
        or config.get("schema_version") != CONFIG_SCHEMA
    ):
        raise _error("unsupported_schema")
    if type(config.get("enabled")) is not bool:
        raise _error("schema_invalid")
    raw_policies = config.get("key_policies")
    if (
        type(raw_policies) is not list
        or not raw_policies
        or len(raw_policies) > MAX_KEYS
    ):
        raise _error("schema_invalid")
    policies = [normalize_key_policy(item) for item in raw_policies]
    policies.sort(key=lambda item: item["key_id"])
    for field in ("key_id", "policy_id", "public_key_sha256"):
        values = [item[field] for item in policies]
        if len(set(values)) != len(values):
            raise _error("schema_invalid")
    return {
        "schema_version": CONFIG_SCHEMA,
        "enabled": config["enabled"],
        "instance_id": _text(config.get("instance_id")),
        "repository": _text(config.get("repository"), REPOSITORY_RE),
        "ledger_id": _text(config.get("ledger_id"), LEDGER_ID_RE),
        "maximum_ttl_seconds": _integer(
            config.get("maximum_ttl_seconds"),
            minimum=MIN_TTL_SECONDS,
            maximum=MAX_TTL_SECONDS,
        ),
        "maximum_clock_skew_seconds": _integer(
            config.get("maximum_clock_skew_seconds"),
            minimum=0,
            maximum=MAX_CLOCK_SKEW_SECONDS,
        ),
        "key_policies": policies,
    }


def parse_config(raw: bytes) -> dict[str, Any]:
    parsed = _parse_json(raw, maximum_bytes=MAX_CONFIG_BYTES)
    normalized = normalize_config(parsed)
    if not hmac.compare_digest(raw, canonical_json(normalized)):
        raise _error("noncanonical_json")
    return normalized


def _normalize_scope(value: Any) -> dict[str, Any]:
    scope = _mapping(value)
    _strict_keys(scope, {"privacy", "visible_to_roles", "repository"})
    privacy = scope.get("privacy")
    if type(privacy) is not str or privacy not in PRIVACY_ORDER:
        raise _error("schema_invalid")
    roles = _ordered_unique(
        scope.get("visible_to_roles"),
        allowed=set(ROLE_ORDER),
        order=ROLE_ORDER,
    )
    if privacy == "private" and "guide" in roles:
        raise _error("scope_denied")
    repository_raw = scope.get("repository")
    repository = (
        None
        if repository_raw is None
        else _text(repository_raw, REPOSITORY_RE)
    )
    return {
        "privacy": str(privacy),
        "visible_to_roles": roles,
        "repository": repository,
    }


def entry_id_for_write_id(write_id: Any) -> str:
    normalized = _text(write_id, WRITE_ID_RE)
    digest = hashlib.sha256(ENTRY_ID_DOMAIN + normalized.encode("ascii")).hexdigest()
    return f"jlce-{digest[:24]}"


def _normalize_expected_head(value: Any) -> dict[str, Any]:
    head = _mapping(value)
    _strict_keys(
        head,
        {
            "schema_version",
            "ledger_id",
            "sequence",
            "head_entry_sha256",
            "ledger_size_bytes",
            "updated_at",
            "head_sha256",
        },
    )
    _validate_canonical_value(head)
    try:
        return continuity._validate_head(head)  # noqa: SLF001
    except continuity.ContinuityError:
        raise _error("schema_invalid") from None


def _normalize_put(
    value: Any,
    *,
    authority: Mapping[str, str],
    issued_at: datetime,
) -> dict[str, Any]:
    put = _mapping(value)
    _strict_keys(
        put,
        {
            "kind",
            "subject",
            "summary",
            "payload",
            "memory_expires_at",
            "supersedes_entry_id",
        },
    )
    kind = put.get("kind")
    intrinsic = OWNER_KINDS if authority["class"] == "owner" else EXTERNAL_KINDS
    if type(kind) is not str or kind not in intrinsic:
        raise _error("kind_denied")
    if (
        type(put.get("subject")) is not str
        or type(put.get("summary")) is not str
        or type(put.get("payload")) is not dict
    ):
        raise _error("schema_invalid")
    _validate_canonical_value(put.get("payload"))
    try:
        subject = continuity._safe_text(  # noqa: SLF001
            put.get("subject"),
            field="subject",
            maximum_bytes=192,
        )
        summary = continuity._safe_text(  # noqa: SLF001
            put.get("summary"),
            field="summary",
            maximum_bytes=continuity.MAX_SUMMARY_BYTES,
        )
        payload = continuity._normalize_payload(  # noqa: SLF001
            str(kind),
            put.get("payload"),
        )
    except (continuity.ContinuityError, UnicodeError):
        raise _error("schema_invalid") from None
    memory_expiry_raw = put.get("memory_expires_at")
    if memory_expiry_raw is None:
        memory_expires_at = None
    else:
        memory_expiry = _utc(memory_expiry_raw)
        if memory_expiry <= issued_at:
            raise _error("time_invalid")
        memory_expires_at = _utc_text(memory_expiry)
    supersedes_raw = put.get("supersedes_entry_id")
    supersedes = (
        None
        if supersedes_raw is None
        else _text(supersedes_raw, ENTRY_ID_RE)
    )
    if kind == "verified_outcome" and supersedes is not None:
        raise _error("kind_denied")
    return {
        "kind": str(kind),
        "subject": subject,
        "summary": summary,
        "payload": payload,
        "memory_expires_at": memory_expires_at,
        "supersedes_entry_id": supersedes,
    }


def _normalize_suppression(value: Any) -> dict[str, str]:
    suppression = _mapping(value)
    _strict_keys(
        suppression,
        {"target_entry_id", "target_entry_sha256", "reason"},
    )
    reason = suppression.get("reason")
    if type(reason) is not str or reason not in SUPPRESSION_REASONS:
        raise _error("schema_invalid")
    return {
        "target_entry_id": _text(
            suppression.get("target_entry_id"),
            ENTRY_ID_RE,
        ),
        "target_entry_sha256": _digest(
            suppression.get("target_entry_sha256")
        ),
        "reason": str(reason),
    }


_EFFECT_BODY_FIELDS = {
    "schema_version",
    "instance_id",
    "repository",
    "ledger_id",
    "expected_head",
    "policy_id",
    "policy_sha256",
    "write_id",
    "issued_at",
    "expires_at",
    "authority",
    "operation",
    "scope",
    "put",
    "suppression",
}


def _normalize_effect_body(value: Any) -> dict[str, Any]:
    effect = _mapping(value)
    _strict_keys(effect, _EFFECT_BODY_FIELDS)
    if (
        type(effect.get("schema_version")) is not str
        or effect.get("schema_version") != EFFECT_SCHEMA
    ):
        raise _error("unsupported_schema")
    instance_id = _text(effect.get("instance_id"))
    repository = _text(effect.get("repository"), REPOSITORY_RE)
    ledger_id = _text(effect.get("ledger_id"), LEDGER_ID_RE)
    expected_head = _normalize_expected_head(effect.get("expected_head"))
    if expected_head["ledger_id"] != ledger_id:
        raise _error("ledger_mismatch")
    policy_id = _text(effect.get("policy_id"))
    policy_sha256 = _digest(effect.get("policy_sha256"))
    write_id = _text(effect.get("write_id"), WRITE_ID_RE)
    issued = _utc(effect.get("issued_at"))
    expires = _utc(effect.get("expires_at"))
    ttl = (expires - issued).total_seconds()
    if ttl < MIN_TTL_SECONDS or ttl > MAX_TTL_SECONDS:
        raise _error("time_invalid")
    if _utc(expected_head["updated_at"]) > issued:
        raise _error("time_invalid")
    authority = _normalize_authority(effect.get("authority"))
    operation = effect.get("operation")
    if type(operation) is not str or operation not in OPERATIONS:
        raise _error("schema_invalid")
    scope = _normalize_scope(effect.get("scope"))
    if scope["repository"] != repository:
        raise _error("scope_denied")
    if operation == "put":
        if effect.get("suppression") is not None:
            raise _error("schema_invalid")
        put = _normalize_put(
            effect.get("put"),
            authority=authority,
            issued_at=issued,
        )
        suppression = None
    else:
        if authority["class"] != "owner" or effect.get("put") is not None:
            raise _error("operation_denied")
        put = None
        suppression = _normalize_suppression(effect.get("suppression"))
    return {
        "schema_version": EFFECT_SCHEMA,
        "instance_id": instance_id,
        "repository": repository,
        "ledger_id": ledger_id,
        "expected_head": expected_head,
        "policy_id": policy_id,
        "policy_sha256": policy_sha256,
        "write_id": write_id,
        "issued_at": _utc_text(issued),
        "expires_at": _utc_text(expires),
        "authority": authority,
        "operation": str(operation),
        "scope": scope,
        "put": put,
        "suppression": suppression,
    }


def effect_binding_sha256(value: Any) -> str:
    """Digest the complete effect projection, excluding its commitment.

    A protected source adapter includes this digest inside its salted source
    commitment preimage.  The digest binds every semantic field and the exact
    expected ledger head, but does not authenticate the upstream source.
    """

    effect = _mapping(value)
    body = dict(effect)
    body.pop("source_commitment", None)
    return _sha256_domain(
        SOURCE_COMMITMENT_DOMAIN,
        _normalize_effect_body(body),
    )


def build_source_commitment(
    *,
    effect: Any,
    kind: Any,
    commitment_sha256: Any,
) -> dict[str, str]:
    """Attach opaque signer metadata; raw source and salt remain signer-side."""

    commitment_kind = _text(kind, COMMITMENT_KIND_RE)
    return {
        "schema_version": SOURCE_COMMITMENT_SCHEMA,
        "kind": commitment_kind,
        "effect_binding_sha256": effect_binding_sha256(effect),
        "commitment_sha256": _digest(commitment_sha256),
    }


def salted_source_commitment_sha256(
    *,
    kind: Any,
    effect_binding_sha256: Any,
    source_event_sha256: Any,
    salt: Any,
) -> str:
    """Compute the exact signer-side salted commitment.

    ``source_event_sha256`` and the 256-bit salt are inputs only.  Neither is
    serialized into the public envelope.  Calling this function proves no
    source authenticity; the protected adapter must first authenticate and
    canonically hash its own upstream event.
    """

    commitment_kind = _text(kind, COMMITMENT_KIND_RE)
    effect_binding = _digest(effect_binding_sha256)
    source_digest = _digest(source_event_sha256)
    if type(salt) is not bytes or len(salt) != 32:
        raise _error("source_commitment_invalid")
    preimage = {
        "schema_version": SOURCE_COMMITMENT_SCHEMA,
        "algorithm": COMMITMENT_ALGORITHM,
        "kind": commitment_kind,
        "effect_binding_sha256": effect_binding,
        "source_event_sha256": source_digest,
        "salt": base64.urlsafe_b64encode(salt)
        .decode("ascii")
        .rstrip("="),
    }
    return hashlib.sha256(
        SALTED_SOURCE_COMMITMENT_DOMAIN + canonical_json(preimage)
    ).hexdigest()


def _normalize_source_commitment(value: Any) -> dict[str, str]:
    commitment = _mapping(value)
    _strict_keys(
        commitment,
        {
            "schema_version",
            "kind",
            "effect_binding_sha256",
            "commitment_sha256",
        },
    )
    if (
        type(commitment.get("schema_version")) is not str
        or commitment.get("schema_version") != SOURCE_COMMITMENT_SCHEMA
    ):
        raise _error("unsupported_schema")
    return {
        "schema_version": SOURCE_COMMITMENT_SCHEMA,
        "kind": _text(commitment.get("kind"), COMMITMENT_KIND_RE),
        "effect_binding_sha256": _digest(
            commitment.get("effect_binding_sha256")
        ),
        "commitment_sha256": _digest(
            commitment.get("commitment_sha256")
        ),
    }


def normalize_effect(value: Any) -> dict[str, Any]:
    effect = _mapping(value)
    _strict_keys(effect, _EFFECT_BODY_FIELDS | {"source_commitment"})
    body = _normalize_effect_body(
        {field: effect.get(field) for field in _EFFECT_BODY_FIELDS}
    )
    commitment = _normalize_source_commitment(
        effect.get("source_commitment")
    )
    expected_binding = effect_binding_sha256(body)
    if not hmac.compare_digest(
        commitment["effect_binding_sha256"],
        expected_binding,
    ):
        raise _error("source_commitment_invalid")
    return {**body, "source_commitment": commitment}


def _ensure_unsigned_envelope_capacity(
    unsigned: Mapping[str, Any],
) -> None:
    # Every canonical Ed25519 signature string is exactly 86 characters, so
    # this placeholder yields the exact final serialized envelope size.
    projected = {**unsigned, "signature": "A" * 86}
    if len(canonical_json(projected)) > MAX_ENVELOPE_BYTES:
        raise _error("size_exceeded")


def prepare_unsigned_envelope(
    *,
    key_id: Any,
    effect: Any,
) -> dict[str, Any]:
    unsigned = {
        "schema_version": ENVELOPE_SCHEMA,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": _text(key_id),
        "effect": normalize_effect(effect),
    }
    _ensure_unsigned_envelope_capacity(unsigned)
    return unsigned


def _normalize_unsigned_envelope(value: Any) -> dict[str, Any]:
    envelope = _mapping(value)
    _strict_keys(
        envelope,
        {"schema_version", "algorithm", "key_id", "effect"},
    )
    if (
        type(envelope.get("schema_version")) is not str
        or envelope.get("schema_version") != ENVELOPE_SCHEMA
    ):
        raise _error("unsupported_schema")
    if (
        type(envelope.get("algorithm")) is not str
        or envelope.get("algorithm") != SIGNATURE_ALGORITHM
    ):
        raise _error("unsupported_algorithm")
    return prepare_unsigned_envelope(
        key_id=envelope.get("key_id"),
        effect=envelope.get("effect"),
    )


def signing_bytes(unsigned_envelope: Any) -> bytes:
    """Return domain-separated public signing bytes.

    This helper contains no private-key operation.  A separately protected
    signer may sign the returned bytes after it authenticates its source.
    """

    return SIGNING_DOMAIN + canonical_json(
        _normalize_unsigned_envelope(unsigned_envelope)
    )


def _decode_signature(value: Any) -> bytes:
    if type(value) is not str or SIGNATURE_RE.fullmatch(value) is None:
        raise _error("signature_invalid")
    try:
        raw = base64.urlsafe_b64decode(value + "==")
    except (ValueError, TypeError):
        raise _error("signature_invalid") from None
    if (
        len(raw) != 64
        or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value
    ):
        raise _error("signature_invalid")
    _validate_ed25519_signature_encoding(raw)
    return raw


def normalize_envelope(value: Any) -> dict[str, Any]:
    envelope = _mapping(value)
    _strict_keys(
        envelope,
        {"schema_version", "algorithm", "key_id", "effect", "signature"},
    )
    unsigned = _normalize_unsigned_envelope(
        {
            "schema_version": envelope.get("schema_version"),
            "algorithm": envelope.get("algorithm"),
            "key_id": envelope.get("key_id"),
            "effect": envelope.get("effect"),
        }
    )
    signature = _decode_signature(envelope.get("signature"))
    normalized = {
        **unsigned,
        "signature": base64.urlsafe_b64encode(signature)
        .decode("ascii")
        .rstrip("="),
    }
    if len(canonical_json(normalized)) > MAX_ENVELOPE_BYTES:
        raise _error("size_exceeded")
    return normalized


def parse_envelope(raw: bytes) -> dict[str, Any]:
    parsed = _parse_json(raw, maximum_bytes=MAX_ENVELOPE_BYTES)
    normalized = normalize_envelope(parsed)
    if not hmac.compare_digest(raw, canonical_json(normalized)):
        raise _error("noncanonical_json")
    return normalized


def public_key_fingerprint(public_key_bytes: Any) -> str:
    if type(public_key_bytes) is not bytes or len(public_key_bytes) != 32:
        raise _error("key_material_invalid")
    _validate_ed25519_prime_order_point(
        public_key_bytes,
        error_code="key_material_invalid",
    )
    return hashlib.sha256(public_key_bytes).hexdigest()


def envelope_sha256(envelope: Any) -> str:
    normalized = normalize_envelope(envelope)
    return _sha256_domain(ENVELOPE_DIGEST_DOMAIN, normalized)


def _selected_policy(
    config: Mapping[str, Any],
    envelope: Mapping[str, Any],
) -> dict[str, Any]:
    matches = [
        policy
        for policy in config["key_policies"]
        if policy["key_id"] == envelope["key_id"]
    ]
    if len(matches) != 1:
        raise _error("key_unknown")
    return matches[0]


def _verify_policy_bindings(
    *,
    config: Mapping[str, Any],
    policy: Mapping[str, Any],
    effect: Mapping[str, Any],
) -> None:
    if effect["instance_id"] != config["instance_id"]:
        raise _error("instance_mismatch")
    if effect["repository"] != config["repository"]:
        raise _error("scope_denied")
    if effect["ledger_id"] != config["ledger_id"]:
        raise _error("ledger_mismatch")
    if (
        effect["policy_id"] != policy["policy_id"]
        or effect["policy_sha256"] != policy_authorization_sha256(policy)
    ):
        raise _error("policy_mismatch")
    if effect["authority"] != policy["authority"]:
        raise _error("authority_mismatch")
    permissions = policy["permissions"]
    if effect["operation"] not in permissions["operations"]:
        raise _error("operation_denied")
    if (
        effect["operation"] == "put"
        and effect["put"]["kind"] not in permissions["entry_kinds"]
    ):
        raise _error("kind_denied")
    if (
        effect["source_commitment"]["kind"]
        not in permissions["source_commitment_kinds"]
    ):
        raise _error("source_commitment_invalid")
    scope = effect["scope"]
    if (
        scope["privacy"] not in permissions["privacy"]
        or not set(scope["visible_to_roles"]).issubset(
            permissions["visible_to_roles"]
        )
        or scope["repository"] != config["repository"]
    ):
        raise _error("scope_denied")
    issued = _utc(effect["issued_at"])
    expires = _utc(effect["expires_at"])
    policy_start = _utc(policy["valid_from"])
    policy_end = _utc(policy["valid_until"])
    ttl = (expires - issued).total_seconds()
    if (
        issued < policy_start
        or expires > policy_end
        or ttl < MIN_TTL_SECONDS
        or ttl > config["maximum_ttl_seconds"]
    ):
        raise _error("time_invalid")


def _verify_cryptographic_history(
    raw_envelope: bytes,
    *,
    config: Any,
    public_keys: Mapping[str, bytes],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    normalized_config = normalize_config(config)
    envelope = parse_envelope(raw_envelope)
    policy = _selected_policy(normalized_config, envelope)
    # Exact dictionaries make lookup inert; arbitrary Mapping implementations
    # can run caller code from get()/iteration.
    if (
        type(public_keys) is not dict
        or not public_keys
        or len(public_keys) > MAX_KEYS
    ):
        raise _error("key_material_invalid")
    for key_id, key_bytes in public_keys.items():
        if (
            type(key_id) is not str
            or TOKEN_RE.fullmatch(key_id) is None
            or type(key_bytes) is not bytes
            or len(key_bytes) != 32
        ):
            raise _error("key_material_invalid")
        _validate_ed25519_prime_order_point(
            key_bytes,
            error_code="key_material_invalid",
        )
    public_key_bytes = public_keys.get(policy["key_id"])
    fingerprint = public_key_fingerprint(public_key_bytes)
    if not hmac.compare_digest(
        fingerprint,
        policy["public_key_sha256"],
    ):
        raise _error("key_fingerprint_mismatch")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except (TypeError, ValueError):
        raise _error("key_material_invalid") from None
    unsigned = {
        "schema_version": envelope["schema_version"],
        "algorithm": envelope["algorithm"],
        "key_id": envelope["key_id"],
        "effect": envelope["effect"],
    }
    signature = _decode_signature(envelope["signature"])
    # _decode_signature has already proved canonical R, prime-order R, and
    # S < L before the backend sees attacker-controlled signature bytes.
    try:
        public_key.verify(
            signature,
            signing_bytes(unsigned),
        )
    except InvalidSignature:
        raise _error("signature_invalid") from None
    _verify_policy_bindings(
        config=normalized_config,
        policy=policy,
        effect=envelope["effect"],
    )
    return normalized_config, envelope, policy


def _derive_continuity_write(
    *,
    envelope: Mapping[str, Any],
) -> dict[str, Any] | None:
    effect = envelope["effect"]
    if effect["operation"] != "put":
        return None
    put = effect["put"]
    authority = effect["authority"]
    request = {
        "schema_version": continuity.WRITE_SCHEMA,
        "entry_id": entry_id_for_write_id(effect["write_id"]),
        "kind": put["kind"],
        "subject": put["subject"],
        "summary": put["summary"],
        "payload": put["payload"],
        "source": {
            "kind": authority["source_kind"],
            "trust": authority["source_trust"],
            "actor": authority["source_actor"],
            "locator": (
                f"signed-continuity:{envelope['key_id']}:{effect['write_id']}"
            ),
            # This is the opaque salted commitment, not an unsalted digest of
            # the private upstream event.
            "sha256": effect["source_commitment"]["commitment_sha256"],
        },
        "scope": effect["scope"],
        "expires_at": put["memory_expires_at"],
        "supersedes_entry_id": put["supersedes_entry_id"],
    }
    try:
        return continuity._normalize_typed_write_request(request)  # noqa: SLF001
    except continuity.ContinuityError:
        # This should be unreachable after effect normalization.  Keeping it
        # fail-closed protects the importer from future schema drift.
        raise _error("schema_invalid") from None


def _verification_result(
    *,
    mode: str,
    envelope: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    effect = envelope["effect"]
    return {
        "schema_version": VERIFICATION_SCHEMA,
        "mode": mode,
        "envelope_sha256": envelope_sha256(envelope),
        "key_id": envelope["key_id"],
        "key_state": policy["state"],
        "source_authentication": "not_proven",
        "derived_entry_id": entry_id_for_write_id(effect["write_id"]),
        "expected_head": effect["expected_head"],
        "continuity_write": _derive_continuity_write(envelope=envelope),
        "suppression": effect["suppression"],
        "effect": effect,
    }


def verify_historical_envelope(
    raw_envelope: bytes,
    *,
    config: Any,
    public_keys: Mapping[str, bytes],
) -> dict[str, Any]:
    """Verify signature/history for active or retired keys."""

    _, envelope, policy = _verify_cryptographic_history(
        raw_envelope,
        config=config,
        public_keys=public_keys,
    )
    if policy["state"] == "revoked":
        raise _error("key_revoked")
    return _verification_result(
        mode="historical",
        envelope=envelope,
        policy=policy,
    )


def verify_for_replay(
    raw_envelope: bytes,
    *,
    config: Any,
    public_keys: Mapping[str, bytes],
    expected_envelope_sha256: Any,
) -> dict[str, Any]:
    """Verify an exact envelope already pinned by durable importer state."""

    _, envelope, policy = _verify_cryptographic_history(
        raw_envelope,
        config=config,
        public_keys=public_keys,
    )
    if policy["state"] == "revoked":
        raise _error("key_revoked")
    expected = _digest(expected_envelope_sha256)
    observed = envelope_sha256(envelope)
    if not hmac.compare_digest(expected, observed):
        raise _error("replay_digest_mismatch")
    return _verification_result(
        mode="replay",
        envelope=envelope,
        policy=policy,
    )


def verify_for_new_admission(
    raw_envelope: bytes,
    *,
    config: Any,
    public_keys: Mapping[str, bytes],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Admit a fresh effect; disabled importers and rotated keys fail closed."""

    normalized_config, envelope, policy = _verify_cryptographic_history(
        raw_envelope,
        config=config,
        public_keys=public_keys,
    )
    if not normalized_config["enabled"]:
        raise _error("importer_disabled")
    if policy["state"] == "retired":
        raise _error("key_retired")
    if policy["state"] == "revoked":
        raise _error("key_revoked")
    current = _now(now)
    skew = timedelta(
        seconds=normalized_config["maximum_clock_skew_seconds"]
    )
    issued = _utc(envelope["effect"]["issued_at"])
    expires = _utc(envelope["effect"]["expires_at"])
    if issued > current and issued - current > skew:
        raise _error("not_yet_valid")
    if current >= expires:
        raise _error("expired")
    return _verification_result(
        mode="new_admission",
        envelope=envelope,
        policy=policy,
    )


__all__ = [
    "COMMITMENT_ALGORITHM",
    "CONFIG_SCHEMA",
    "ContinuityProtocolError",
    "EFFECT_SCHEMA",
    "ENVELOPE_SCHEMA",
    "ERROR_SCHEMA",
    "KEY_POLICY_SCHEMA",
    "SIGNATURE_ALGORITHM",
    "SOURCE_COMMITMENT_SCHEMA",
    "VERIFICATION_SCHEMA",
    "build_source_commitment",
    "canonical_json",
    "effect_binding_sha256",
    "entry_id_for_write_id",
    "envelope_sha256",
    "normalize_config",
    "normalize_effect",
    "normalize_envelope",
    "normalize_key_policy",
    "parse_config",
    "parse_envelope",
    "policy_authorization_sha256",
    "prepare_unsigned_envelope",
    "public_error",
    "public_key_fingerprint",
    "salted_source_commitment_sha256",
    "signing_bytes",
    "verify_for_new_admission",
    "verify_for_replay",
    "verify_historical_envelope",
]
