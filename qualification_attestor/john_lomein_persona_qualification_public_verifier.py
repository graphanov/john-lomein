#!/usr/bin/env python3
"""Zero-argument offline verification of John Lomein's public trust object."""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from qualification_attestor import (
    john_lomein_persona_qualification_attestor as core,
)
from qualification_attestor import (
    john_lomein_persona_qualification_trust_projection as trust,
)


PIN_CONFIG_SCHEMA = (
    "john-lomein.persona-qualification-public-verifier-config.v1"
)
RESULT_SCHEMA = (
    "john-lomein.persona-qualification-public-verification.v1"
)
DEFAULT_PIN_CONFIG_PATH = Path(
    (
        "/private/etc/john-lomein/"
        "persona-qualification-public-verifier.json"
        if sys.platform == "darwin"
        else "/etc/john-lomein/"
        "persona-qualification-public-verifier.json"
    )
)
MAX_PIN_CONFIG_BYTES = 64 * 1024
PIN_CONFIG_FIELDS = {
    "schema_version",
    "projection_path",
    "instance_slug",
    "attestor_key_id",
    "public_key_sha256",
}


class PublicQualificationVerifierError(ValueError):
    """One privacy-safe public verification rejection."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _error(code: str) -> PublicQualificationVerifierError:
    return PublicQualificationVerifierError(code)


def normalize_pin_config(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != PIN_CONFIG_FIELDS:
        raise _error("public_verifier_config_fields_invalid")
    if value.get("schema_version") != PIN_CONFIG_SCHEMA:
        raise _error("public_verifier_config_schema_unsupported")
    try:
        projection_text = core._absolute_path(
            value.get("projection_path"),
            field="public_verifier_projection_path",
        )
        slug = core._slug(
            value.get("instance_slug"),
            field="public_verifier_instance_slug",
        )
        key_id = core._token(
            value.get("attestor_key_id"),
            field="public_verifier_key_id",
        )
        fingerprint = core._digest(
            value.get("public_key_sha256"),
            field="public_verifier_public_key_sha256",
        )
    except core.QualificationAttestorError as exc:
        raise _error(exc.code) from exc
    projection = Path(projection_text)
    if not projection.name or projection.name.startswith("."):
        raise _error("public_verifier_projection_path_invalid")
    return {
        "schema_version": PIN_CONFIG_SCHEMA,
        "projection_path": str(projection),
        "instance_slug": slug,
        "attestor_key_id": key_id,
        "public_key_sha256": fingerprint,
    }


def read_pin_config(
    path: Path = DEFAULT_PIN_CONFIG_PATH,
    *,
    installation_owner_uid: int = 0,
) -> dict[str, Any]:
    pin_path = Path(path)
    try:
        raw = core._read_trusted_file(
            pin_path,
            field="public_verifier_config",
            expected_owner_uid=installation_owner_uid,
            maximum_bytes=MAX_PIN_CONFIG_BYTES,
        )
    except core.QualificationAttestorError as exc:
        raise _error(exc.code) from exc
    try:
        info = pin_path.lstat()
    except OSError as exc:
        raise _error("public_verifier_config_unreadable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != installation_owner_uid
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o444
    ):
        raise _error("public_verifier_config_unsafe")
    try:
        parsed = core.parse_json_bytes(
            raw,
            field="public_verifier_config",
            maximum_bytes=MAX_PIN_CONFIG_BYTES,
        )
    except core.QualificationAttestorError as exc:
        raise _error(exc.code) from exc
    normalized = normalize_pin_config(parsed)
    if raw != core.canonical_json(normalized) + b"\n":
        raise _error("public_verifier_config_noncanonical")
    return normalized


def verify_installed_projection(
    pin_config_path: Path = DEFAULT_PIN_CONFIG_PATH,
    *,
    now_unix: int | None = None,
    installation_owner_uid: int = 0,
    projection_owner_uid: int = 0,
) -> dict[str, Any]:
    """Verify public proof against installer-pinned identity, without network."""

    pins = read_pin_config(
        pin_config_path,
        installation_owner_uid=installation_owner_uid,
    )
    now = (
        int(time.time())
        if now_unix is None
        else now_unix
    )
    if type(now) is not int or now < 1:
        raise _error("public_verifier_clock_invalid")
    try:
        projection = trust.read_public_projection(
            Path(pins["projection_path"]),
            publication_owner_uid=projection_owner_uid,
        )
        verified = trust.verify_projection(
            projection,
            expected_instance_slug=pins["instance_slug"],
            expected_key_id=pins["attestor_key_id"],
            expected_public_key_sha256=pins["public_key_sha256"],
            now_unix=now,
        )
    except trust.TrustProjectionError as exc:
        raise _error(exc.code) from exc
    head = verified["head"]
    return {
        "schema_version": RESULT_SCHEMA,
        "status": "verified",
        "instance_slug": head["instance_slug"],
        "attestor_key_id": pins["attestor_key_id"],
        "public_key_sha256": pins["public_key_sha256"],
        "run_id": head["run_id"],
        "chain_sequence": head["chain_sequence"],
        "attestation_sha256": head["attestation_sha256"],
        "projection_sha256": core.sha256_json(verified),
        "summary_sha256": head["summary_sha256"],
        "binding_sha256": head["binding_sha256"],
        "qualified_at_unix": head["qualified_at_unix"],
        "verified_at_unix": head["verified_at_unix"],
        "expires_at_unix": head["expires_at_unix"],
        "claim_strength": core.CLAIM_STRENGTH,
        "public_reputation_eligible": False,
        "claim_limits": verified["claim_limits"],
        "checked_at_unix": now,
    }


def _emit(value: Mapping[str, Any]) -> None:
    print(
        json.dumps(
            dict(value),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(argv if argv is not None else os.sys.argv[1:])
    try:
        if arguments:
            raise _error("command_arguments_unsupported")
        result = verify_installed_projection()
    except PublicQualificationVerifierError as exc:
        _emit(
            {
                "schema_version": RESULT_SCHEMA,
                "status": "invalid",
                "reason": exc.code,
            }
        )
        return 2
    _emit(result)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
