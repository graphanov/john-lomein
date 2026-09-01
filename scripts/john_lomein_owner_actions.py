#!/usr/bin/env python3
"""Shared owner-action, notification, and Discord trust helpers."""
from __future__ import annotations

import hashlib
import base64
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ACTION_OWNER = "owner_action"
ACTION_AUTOMATION_BLOCKER = "automation_blocker"
ACTION_CODEX_PENDING = "codex_pending"
ACTION_TRIAGE = "triage_actionable"
ACTION_NOISE = "ignored_noise"

TRUST_OWNER = "owner"
TRUST_COLLABORATOR = "collaborator"
TRUST_PUBLIC = "public"
TRUST_UNTRUSTED = "untrusted"
TRUST_TIERS = {TRUST_OWNER, TRUST_COLLABORATOR, TRUST_PUBLIC, TRUST_UNTRUSTED}

DIRTY_CHECKOUT_RECOVERY = "recovery=inspect_status_then_stash_commit_or_clean_before_rerun;do_not_reset_or_delete"
TRUST_ASSERTION_MAX_AGE_SECONDS = 10 * 60
MAX_TRUST_PUBLIC_KEY_BYTES = 64 * 1024
PUBLISH_WORKFLOW_CONTRACT_VERSION = "john-lomein-publish/v1"
SAFE_NPM_DIST_TAG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
RELEASE_BUNDLE_V5_SCHEMA = "john-lomein.release-bundle.v6"
RELEASE_BUNDLE_V4_SCHEMAS = {
    "john-lomein.release-bundle.v4",
    "john_lomein_release_bundle/v4",
}
RELEASE_BUNDLE_V5_RISK_CLASSES = {"low", "medium", "high", "critical"}
RELEASE_BUNDLE_V5_ROOT_FIELDS = {
    "schema_version",
    "bundle_id",
    "bundle_digest",
    "instance_slug",
    "repository",
    "created_at",
    "expires_at",
    "initial_base_sha",
    "merge_method",
    "publish",
    "train_attestation_digest",
    "actions",
    "ordered_prs",
}
RELEASE_BUNDLE_V5_AUTHORITY_FIELDS = RELEASE_BUNDLE_V5_ROOT_FIELDS - {
    "bundle_id",
    "bundle_digest",
}
RELEASE_BUNDLE_V5_PR_FIELDS = {
    "position",
    "number",
    "url",
    "head_sha",
    "expected_merge_tree_sha",
    "base_branch",
    "author_login",
    "changed_paths",
    "changed_paths_digest",
    "changed_path_count",
    "risk_class",
    "review_quorum_sha256",
    "review_quorum_policy_sha256",
}
RELEASE_BUNDLE_OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
RELEASE_BUNDLE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RELEASE_BUNDLE_INSTANCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RELEASE_BUNDLE_REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
RELEASE_BUNDLE_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
RELEASE_BUNDLE_AUTHOR_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,98}(?:\[bot\])?)?$"
)
RELEASE_BUNDLE_MAX_SAFE_INTEGER = 9_007_199_254_740_991
RELEASE_BUNDLE_MAX_PRS = 50
RELEASE_BUNDLE_MAX_CHANGED_PATHS = 2000
RELEASE_BUNDLE_MAX_CHANGED_PATH_BYTES = 1024


def split_csv(raw: object) -> list[str]:
    """Split comma/semicolon separated config values without splitting label words.

    GitHub labels may contain spaces, so whitespace cannot be a delimiter here.
    Callers that need whitespace tokenization must do it explicitly at that trust
    boundary instead of using this config parser.
    """
    out: list[str] = []
    if isinstance(raw, (list, tuple, set)):
        parts = [str(x) for x in raw]
    else:
        parts = re.split(r"[,;]+", str(raw or ""))
    for part in parts:
        value = str(part).strip()
        if value and value not in out:
            out.append(value)
    return out


def stable_fingerprint(payload: Any) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:20]


def stable_sha256(payload: Any) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def normalized_text_hash(text: str) -> str:
    normalized = " ".join(str(text or "").strip().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def validate_npm_dist_tag(value: object) -> tuple[str, str]:
    tag = str(value or "").strip()
    if not tag or not SAFE_NPM_DIST_TAG_RE.fullmatch(tag):
        return "", "publish_npm_tag_invalid"
    return tag, ""


def publish_workflow_contract_text(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "publish_contract_version": PUBLISH_WORKFLOW_CONTRACT_VERSION,
        "publish_contract_valid": False,
        "publish_workflow_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "blocker": "",
    }
    try:
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
    except Exception as exc:
        result["blocker"] = f"publish_workflow_contract_yaml_invalid:{exc}"
        return result
    if not isinstance(workflow, dict):
        result["blocker"] = "publish_workflow_contract_root_invalid"
        return result
    workflow_env = workflow.get("env") or {}
    if not isinstance(workflow_env, dict) or str(workflow_env.get("JOHN_LOMEIN_PUBLISH_CONTRACT") or "") != PUBLISH_WORKFLOW_CONTRACT_VERSION:
        result["blocker"] = "publish_workflow_contract_marker_missing"
        return result
    triggers = workflow.get("on") or {}
    dispatch = triggers.get("workflow_dispatch") if isinstance(triggers, dict) else None
    inputs = dispatch.get("inputs") if isinstance(dispatch, dict) else None
    if not isinstance(inputs, dict):
        result["blocker"] = "publish_workflow_contract_dispatch_inputs_missing"
        return result
    for name in ("expected-sha", "expected-version", "npm-tag"):
        spec = inputs.get(name)
        required = str((spec or {}).get("required") or "").strip().lower() if isinstance(spec, dict) else ""
        if required != "true":
            result["blocker"] = f"publish_workflow_contract_input_missing_or_optional:{name}"
            return result
    jobs = workflow.get("jobs") or {}
    if not isinstance(jobs, dict):
        result["blocker"] = "publish_workflow_contract_jobs_missing"
        return result
    publish_steps = 0
    expected_sha_expression = "${{inputs.expected-sha}}"
    github_sha_expression = "${{github.sha}}"
    expected_version_expression = "${{inputs.expected-version}}"
    npm_tag_expression = "${{inputs.npm-tag}}"
    for job_name, job in jobs.items():
        steps = job.get("steps") if isinstance(job, dict) else None
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            run_text = str(step.get("run") or "")
            if not re.search(r"(^|[\s;&|])npm\s+publish(?:\s|$)", run_text):
                continue
            publish_steps += 1
            guarded = False
            for earlier in steps[:index]:
                if not isinstance(earlier, dict):
                    continue
                earlier_env = earlier.get("env") or {}
                earlier_run = str(earlier.get("run") or "")
                if not isinstance(earlier_env, dict):
                    continue
                expected_sha = re.sub(r"\s+", "", str(earlier_env.get("EXPECTED_SHA") or ""))
                actual_sha = re.sub(r"\s+", "", str(earlier_env.get("ACTUAL_SHA") or ""))
                expected_version = re.sub(r"\s+", "", str(earlier_env.get("EXPECTED_VERSION") or ""))
                guard_lines = {line.strip() for line in earlier_run.splitlines()}
                if (
                    expected_sha == expected_sha_expression
                    and actual_sha == github_sha_expression
                    and expected_version == expected_version_expression
                    and 'test "$ACTUAL_SHA" = "$EXPECTED_SHA"' in guard_lines
                    and 'ACTUAL_VERSION="$(node -p "require(\'./package.json\').version")"' in guard_lines
                    and 'test "$ACTUAL_VERSION" = "$EXPECTED_VERSION"' in guard_lines
                    and not str(earlier.get("if") or "").strip()
                    and str(earlier.get("continue-on-error") or "false").strip().lower() != "true"
                ):
                    guarded = True
                    break
            if not guarded:
                result["blocker"] = f"publish_workflow_contract_sha_guard_missing:{job_name}"
                return result
            if str(step.get("if") or "").strip():
                result["blocker"] = f"publish_workflow_contract_publish_condition_forbidden:{job_name}"
                return result
            step_env = step.get("env") or {}
            bound_tag = re.sub(r"\s+", "", str(step_env.get("NPM_TAG") or "")) if isinstance(step_env, dict) else ""
            if bound_tag != npm_tag_expression or not re.search(r"--tag(?:=|\s+)[\"']?\$NPM_TAG(?:[\"']?)(?:\s|$)", run_text):
                result["blocker"] = f"publish_workflow_contract_npm_tag_unbound:{job_name}"
                return result
    if publish_steps == 0:
        result["blocker"] = "publish_workflow_contract_publish_step_missing"
        return result
    result["publish_contract_valid"] = True
    return result


def publish_workflow_contract(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink():
            return {
                "publish_contract_version": PUBLISH_WORKFLOW_CONTRACT_VERSION,
                "publish_contract_valid": False,
                "publish_workflow_sha256": "",
                "blocker": "publish_workflow_contract_symlink",
            }
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        return {
            "publish_contract_version": PUBLISH_WORKFLOW_CONTRACT_VERSION,
            "publish_contract_valid": False,
            "publish_workflow_sha256": "",
            "blocker": f"publish_workflow_contract_unreadable:{exc}",
        }
    return publish_workflow_contract_text(text)


def _release_bundle_canonical_text(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > RELEASE_BUNDLE_MAX_SAFE_INTEGER:
            raise ValueError("release_bundle_v5_integer_out_of_range")
        return str(value)
    if isinstance(value, float):
        raise ValueError("release_bundle_v5_float_forbidden")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise ValueError("release_bundle_v5_string_not_nfc")
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
    if isinstance(value, list):
        return (
            "["
            + ",".join(_release_bundle_canonical_text(item) for item in value)
            + "]"
        )
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("release_bundle_v5_object_key_invalid")
        keys = sorted(
            value,
            key=lambda key: key.encode("utf-16-be", errors="strict"),
        )
        return (
            "{"
            + ",".join(
                f"{_release_bundle_canonical_text(key)}:"
                f"{_release_bundle_canonical_text(value[key])}"
                for key in keys
            )
            + "}"
        )
    raise ValueError("release_bundle_v5_canonical_type_invalid")


def release_bundle_canonical_json(value: Any) -> bytes:
    return _release_bundle_canonical_text(value).encode("utf-8")


def release_bundle_changed_paths_digest(paths: list[str]) -> str:
    """Digest one canonical changed-path array without reordering it."""
    return (
        "sha256:"
        + hashlib.sha256(release_bundle_canonical_json(paths)).hexdigest()
    )


def release_bundle_id_from_digest(digest: str) -> str:
    value = str(digest or "")
    if not RELEASE_BUNDLE_DIGEST_RE.fullmatch(value):
        raise ValueError("release_bundle_v5_digest_invalid")
    return f"jlb-{value.removeprefix('sha256:')[:24]}"


def _release_bundle_v5_timestamp(value: object, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"release_bundle_v5_{field}_invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError(f"release_bundle_v5_{field}_invalid") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _release_bundle_v5_authority(
    bundle: dict[str, Any],
    *,
    complete_root: bool,
) -> dict[str, Any]:
    if not isinstance(bundle, dict):
        raise ValueError("release_bundle_v5_root_invalid")
    expected = (
        RELEASE_BUNDLE_V5_ROOT_FIELDS
        if complete_root
        else RELEASE_BUNDLE_V5_AUTHORITY_FIELDS
    )
    if set(bundle) != expected:
        raise ValueError("release_bundle_v5_root_fields_invalid")
    if bundle.get("schema_version") != RELEASE_BUNDLE_V5_SCHEMA:
        raise ValueError("release_bundle_v5_schema_invalid")

    instance_slug = bundle.get("instance_slug")
    if (
        not isinstance(instance_slug, str)
        or not RELEASE_BUNDLE_INSTANCE_RE.fullmatch(instance_slug)
    ):
        raise ValueError("release_bundle_v5_instance_invalid")

    repository = bundle.get("repository")
    if not isinstance(repository, dict) or set(repository) != {
        "full_name",
        "id",
        "default_branch",
    }:
        raise ValueError("release_bundle_v5_repository_invalid")
    full_name = repository.get("full_name")
    if (
        not isinstance(full_name, str)
        or not RELEASE_BUNDLE_REPOSITORY_RE.fullmatch(full_name)
    ):
        raise ValueError("release_bundle_v5_repository_name_invalid")
    repository_id = repository.get("id")
    if (
        isinstance(repository_id, bool)
        or not isinstance(repository_id, int)
        or repository_id <= 0
        or repository_id > RELEASE_BUNDLE_MAX_SAFE_INTEGER
    ):
        raise ValueError("release_bundle_v5_repository_id_invalid")
    default_branch = repository.get("default_branch")
    if (
        not isinstance(default_branch, str)
        or not RELEASE_BUNDLE_BRANCH_RE.fullmatch(default_branch)
    ):
        raise ValueError("release_bundle_v5_default_branch_invalid")

    created = _release_bundle_v5_timestamp(
        bundle.get("created_at"), field="created_at"
    )
    expires = _release_bundle_v5_timestamp(
        bundle.get("expires_at"), field="expires_at"
    )
    ttl_seconds = int((expires - created).total_seconds())
    if ttl_seconds < 60 or ttl_seconds > 24 * 60 * 60:
        raise ValueError("release_bundle_v5_expiry_invalid")
    initial_base_sha = bundle.get("initial_base_sha")
    if (
        not isinstance(initial_base_sha, str)
        or not RELEASE_BUNDLE_OID_RE.fullmatch(initial_base_sha)
    ):
        raise ValueError("release_bundle_v5_initial_base_sha_invalid")
    if bundle.get("merge_method") != "squash":
        raise ValueError("release_bundle_v5_merge_method_invalid")
    if bundle.get("publish") is not False:
        raise ValueError("release_bundle_v5_publish_invalid")
    if bundle.get("train_attestation_digest") is not None:
        raise ValueError("release_bundle_v5_train_attestation_digest_invalid")
    if bundle.get("actions") != {"merge": True, "publish": False}:
        raise ValueError("release_bundle_v5_actions_invalid")

    ordered_prs = bundle.get("ordered_prs")
    if (
        not isinstance(ordered_prs, list)
        or not ordered_prs
        or len(ordered_prs) > RELEASE_BUNDLE_MAX_PRS
    ):
        raise ValueError("release_bundle_v5_ordered_prs_invalid")
    seen_numbers: set[int] = set()
    for expected_position, item in enumerate(ordered_prs):
        if not isinstance(item, dict) or set(item) != RELEASE_BUNDLE_V5_PR_FIELDS:
            raise ValueError("release_bundle_v5_pr_fields_invalid")
        position = item.get("position")
        if (
            isinstance(position, bool)
            or not isinstance(position, int)
            or position != expected_position
        ):
            raise ValueError("release_bundle_v5_pr_position_invalid")
        number = item.get("number")
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or number <= 0
            or number > 2**31 - 1
        ):
            raise ValueError("release_bundle_v5_pr_number_invalid")
        if number in seen_numbers:
            raise ValueError("release_bundle_v5_pr_number_duplicate")
        seen_numbers.add(number)
        url = item.get("url")
        if (
            not isinstance(url, str)
            or url != f"https://github.com/{full_name}/pull/{number}"
        ):
            raise ValueError("release_bundle_v5_pr_url_invalid")
        head_sha = item.get("head_sha")
        if (
            not isinstance(head_sha, str)
            or not RELEASE_BUNDLE_OID_RE.fullmatch(head_sha)
        ):
            raise ValueError("release_bundle_v5_pr_head_sha_invalid")
        expected_merge_tree_sha = item.get("expected_merge_tree_sha")
        if (
            not isinstance(expected_merge_tree_sha, str)
            or not RELEASE_BUNDLE_OID_RE.fullmatch(
                expected_merge_tree_sha
            )
        ):
            raise ValueError(
                "release_bundle_v5_pr_expected_merge_tree_sha_invalid"
            )
        if item.get("base_branch") != default_branch:
            raise ValueError("release_bundle_v5_pr_base_branch_invalid")
        author_login = item.get("author_login")
        if (
            not isinstance(author_login, str)
            or not RELEASE_BUNDLE_AUTHOR_RE.fullmatch(author_login)
        ):
            raise ValueError("release_bundle_v5_pr_author_invalid")
        paths = item.get("changed_paths")
        if (
            not isinstance(paths, list)
            or not all(isinstance(path, str) for path in paths)
            or paths != sorted(paths)
            or len(paths) != len(set(paths))
            or len(paths) > RELEASE_BUNDLE_MAX_CHANGED_PATHS
        ):
            raise ValueError("release_bundle_v5_changed_paths_invalid")
        for path in paths:
            parts = path.split("/")
            if (
                not path
                or path.startswith("/")
                or path.startswith("./")
                or path.endswith("/")
                or "\\" in path
                or "\x00" in path
                or len(path.encode("utf-8"))
                > RELEASE_BUNDLE_MAX_CHANGED_PATH_BYTES
                or any(part in {"", ".", ".."} for part in parts)
            ):
                raise ValueError("release_bundle_v5_changed_path_invalid")
        path_count = item.get("changed_path_count")
        if (
            isinstance(path_count, bool)
            or not isinstance(path_count, int)
            or path_count != len(paths)
        ):
            raise ValueError("release_bundle_v5_changed_path_count_invalid")
        paths_digest = item.get("changed_paths_digest")
        if (
            not isinstance(paths_digest, str)
            or paths_digest != release_bundle_changed_paths_digest(paths)
        ):
            raise ValueError("release_bundle_v5_changed_paths_digest_invalid")
        if item.get("risk_class") not in RELEASE_BUNDLE_V5_RISK_CLASSES:
            raise ValueError("release_bundle_v5_risk_class_invalid")
        if any(
            not isinstance(item.get(field), str)
            or RELEASE_BUNDLE_DIGEST_RE.fullmatch(item[field]) is None
            for field in ("review_quorum_sha256", "review_quorum_policy_sha256")
        ):
            raise ValueError("release_bundle_v5_review_quorum_digest_invalid")

    authority = {field: bundle[field] for field in RELEASE_BUNDLE_V5_AUTHORITY_FIELDS}
    if complete_root:
        stored_digest = bundle.get("bundle_digest")
        if (
            not isinstance(stored_digest, str)
            or not RELEASE_BUNDLE_DIGEST_RE.fullmatch(stored_digest)
        ):
            raise ValueError("release_bundle_v5_bundle_digest_invalid")
        bundle_id = bundle.get("bundle_id")
        if (
            not isinstance(bundle_id, str)
            or bundle_id != release_bundle_id_from_digest(stored_digest)
        ):
            raise ValueError("release_bundle_v5_bundle_id_invalid")
    return authority


def release_bundle_v5_content_digest(authority: dict[str, Any]) -> str:
    protected = _release_bundle_v5_authority(authority, complete_root=False)
    return (
        "sha256:"
        + hashlib.sha256(
            release_bundle_canonical_json(protected)
        ).hexdigest()
    )


def _release_bundle_digest_v4(bundle: dict[str, Any]) -> str:
    def normalized_files(pr: dict[str, Any]) -> list[str]:
        paths: list[str] = []
        for item in pr.get("files") or []:
            path = str(item.get("path") or "") if isinstance(item, dict) else str(item or "")
            if path and path not in paths:
                paths.append(path)
        return sorted(paths)

    clean_prs = []
    for raw_pr in bundle.get("clean_prs") or []:
        pr = raw_pr if isinstance(raw_pr, dict) else {}
        try:
            number = int(pr.get("number") or 0)
        except (TypeError, ValueError):
            number = 0
        clean_prs.append(
            {
                "number": number,
                "headRefOid": str(pr.get("headRefOid") or ""),
                "baseRefName": str(pr.get("baseRefName") or ""),
                "baseRefOid": str(pr.get("baseRefOid") or ""),
                "targetBaseOid": str(pr.get("targetBaseOid") or ""),
                "files": normalized_files(pr),
            }
        )
    publish_raw = bundle.get("publish_readiness")
    publish = publish_raw if isinstance(publish_raw, dict) else {}
    publish_request_raw = bundle.get("publish_request")
    publish_request = publish_request_raw if isinstance(publish_request_raw, dict) else {}
    approved_actions_raw = bundle.get("approved_actions")
    approved_actions = approved_actions_raw if isinstance(approved_actions_raw, dict) else {}
    protected = {
        "schema_version": "john_lomein_release_bundle_digest/v4",
        "bundle_id": str(bundle.get("bundle_id") or ""),
        "repo": str(bundle.get("repo") or ""),
        "clean_prs": sorted(clean_prs, key=lambda item: item["number"]),
        "blockers": sorted(str(x) for x in (bundle.get("blockers") or [])),
        "approved_actions": {
            "merge": bool(approved_actions.get("merge")),
            "publish": bool(approved_actions.get("publish")),
        },
        "publish_request": {
            "npm_tag": str(publish_request.get("npm_tag") or ""),
        },
        "publish_readiness": {
            "package_name": str(publish.get("package_name") or publish.get("name") or ""),
            "package_version": str(publish.get("package_version") or publish.get("version") or ""),
            "publish_workflow_name": str(publish.get("publish_workflow_name") or ""),
            "publish_ready_after_merge": bool(publish.get("publish_ready_after_merge") or publish.get("publish_ready")),
            "conditional_after_merge": bool(publish.get("conditional_after_merge")),
            "blocker": str(publish.get("blocker") or ""),
            "publish_contract_version": str(publish.get("publish_contract_version") or ""),
            "publish_workflow_sha256": str(publish.get("publish_workflow_sha256") or ""),
        },
        "allowed_after_gate": [str(x) for x in (bundle.get("allowed_after_gate") or [])],
        "forbidden_without_gate": [str(x) for x in (bundle.get("forbidden_without_gate") or [])],
    }
    return stable_sha256(protected)


def release_bundle_digest(bundle: dict[str, Any]) -> str:
    """Return the strict v5 digest or the historical v4-compatible digest."""
    if not isinstance(bundle, dict):
        raise ValueError("release_bundle_root_invalid")
    schema = bundle.get("schema_version")
    if schema == RELEASE_BUNDLE_V5_SCHEMA:
        authority = _release_bundle_v5_authority(bundle, complete_root=True)
        return release_bundle_v5_content_digest(authority)
    if schema is not None and schema not in RELEASE_BUNDLE_V4_SCHEMAS:
        raise ValueError("release_bundle_schema_unsupported")
    return _release_bundle_digest_v4(bundle)


def release_owner_approval_text(bundle: dict[str, Any]) -> str:
    bundle_id = str(bundle.get("bundle_id") or "")
    digest = str(bundle.get("bundle_digest") or "")
    if bundle.get("schema_version") == RELEASE_BUNDLE_V5_SCHEMA:
        try:
            computed = release_bundle_digest(bundle)
        except (TypeError, ValueError):
            return ""
        if computed != digest:
            return ""
        actions = bundle.get("actions")
        merge = (
            bundle.get("merge_method") == "squash"
            and bundle.get("publish") is False
            and isinstance(actions, dict)
            and actions.get("merge") is True
        )
        publish = isinstance(actions, dict) and actions.get("publish") is True
    else:
        actions_raw = bundle.get("approved_actions")
        actions = actions_raw if isinstance(actions_raw, dict) else {}
        merge = bool(actions.get("merge"))
        publish = bool(actions.get("publish"))
    if not bundle_id or not digest or not merge:
        return ""
    prefix = (
        f"APPROVE JOHN-LOMEIN BUNDLE {bundle_id} DIGEST {digest}: "
        "squash-merge the listed PR with the protected release broker;"
    )
    if not publish:
        return (
            f"{prefix} DO NOT publish. Post-merge repository verification "
            "and any publication require separate gates."
        )
    request_raw = bundle.get("publish_request")
    request = request_raw if isinstance(request_raw, dict) else {}
    tag, error = validate_npm_dist_tag(request.get("npm_tag"))
    if error:
        return ""
    return f"{prefix} publish only through the protected broker with npm dist-tag `{tag}`."


def trust_public_key_path(env: dict[str, str]) -> Path:
    home = Path(env.get("BOT_HERMES_HOME") or env.get("HERMES_HOME") or "").expanduser()
    return home / "state" / "gateway" / "trust-assertion.public.pem"


def load_trust_public_key(env: dict[str, str]) -> tuple[bytes | None, str]:
    path = trust_public_key_path(env)
    expected_fingerprint = str(env.get("BOT_TRUST_PUBLIC_KEY_SHA256") or "").strip().lower()
    if not expected_fingerprint:
        return None, "fingerprint_missing"
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None, "missing"
    except OSError as exc:
        if path.is_symlink():
            return None, "symlink"
        return None, f"open_failed:{exc}"
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            return None, "not_regular"
        if metadata.st_mode & 0o222:
            return None, "permissions_writable"
        if metadata.st_size < 1 or metadata.st_size > MAX_TRUST_PUBLIC_KEY_BYTES:
            return None, "size_invalid"
        chunks: list[bytes] = []
        remaining = MAX_TRUST_PUBLIC_KEY_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 16 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    except OSError as exc:
        return None, f"read_failed:{exc}"
    finally:
        os.close(fd)
    if len(data) < 1 or len(data) > MAX_TRUST_PUBLIC_KEY_BYTES:
        return None, "size_invalid"
    text = data.decode("utf-8", errors="ignore")
    if "PUBLIC KEY" not in text:
        return None, "invalid"
    actual_fingerprint = hashlib.sha256(data).hexdigest().lower()
    if actual_fingerprint != expected_fingerprint:
        return None, "fingerprint_mismatch"
    return data, ""


def verify_trust_signature(env: dict[str, str], payload: dict[str, Any], signature: str) -> str:
    key_bytes, key_error = load_trust_public_key(env)
    if key_error or key_bytes is None:
        return f"public_key_{key_error}"
    openssl = ("/opt/homebrew/bin/openssl" if Path("/opt/homebrew/bin/openssl").exists() else "") or ("/usr/bin/openssl" if Path("/usr/bin/openssl").exists() else "")
    if not openssl:
        return "openssl_missing"
    try:
        sig = base64.b64decode(signature.encode("ascii"), validate=True)
    except Exception:
        return "signature_not_base64"
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    with tempfile.TemporaryDirectory(prefix="jl-trust-") as tmp:
        key_path = Path(tmp) / "public.pem"
        body_path = Path(tmp) / "payload.json"
        sig_path = Path(tmp) / "payload.sig"
        key_path.write_bytes(key_bytes)
        key_path.chmod(0o400)
        body_path.write_bytes(body)
        sig_path.write_bytes(sig)
        try:
            proc = subprocess.run([openssl, "dgst", "-sha256", "-verify", str(key_path), "-signature", str(sig_path), str(body_path)], capture_output=True, text=True, timeout=10)
        except Exception as exc:
            return f"verify_failed:{exc}"
    return "" if proc.returncode == 0 else "bad_signature"


def verify_trust_assertion(env: dict[str, str], assertion: str, *, purpose: str, expected: dict[str, Any] | None = None, now: float | None = None) -> tuple[bool, dict[str, Any], str]:
    if not assertion:
        return False, {}, "missing"
    try:
        data = json.loads(assertion)
    except Exception:
        return False, {}, "invalid_json"
    payload = data.get("payload") if isinstance(data, dict) else None
    signature = str((data or {}).get("signature") or "") if isinstance(data, dict) else ""
    if not isinstance(payload, dict) or not signature:
        return False, {}, "malformed"
    signature_error = verify_trust_signature(env, payload, signature)
    if signature_error:
        return False, {}, signature_error
    if str(payload.get("purpose") or "") != purpose:
        return False, payload, "wrong_purpose"
    try:
        issued_at = float(payload.get("iat") or 0)
    except Exception:
        issued_at = 0
    current = time.time() if now is None else now
    if issued_at <= 0 or abs(current - issued_at) > TRUST_ASSERTION_MAX_AGE_SECONDS:
        return False, payload, "expired"
    if not str(payload.get("actor") or "").strip():
        return False, payload, "missing_actor"
    if not str(payload.get("nonce") or "").strip():
        return False, payload, "missing_nonce"
    for key, value in (expected or {}).items():
        if str(payload.get(key) or "") != str(value):
            return False, payload, f"{key}_mismatch"
    nonce = str(payload.get("nonce") or "")
    action_identity = {
        key: payload.get(key)
        for key in [
            "repo",
            "issue",
            "route",
            "bundle_id",
            "bundle_digest",
            "approval_hash",
            "request_id",
            "request_digest",
            "target",
            "target_base_sha256",
        ]
        if payload.get(key) is not None
    }
    nonce_id = hashlib.sha256(json.dumps({"purpose": purpose, "nonce": nonce, "action": action_identity}, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()
    nonce_root = trust_public_key_path(env).parent / "consumed-nonces" / purpose
    nonce_root.mkdir(parents=True, exist_ok=True)
    nonce_path = nonce_root / f"{nonce_id}.json"
    try:
        fd = os.open(nonce_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False, payload, "replay"
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"iat": issued_at, "actor": payload.get("actor"), "purpose": purpose, "action": action_identity}, f, sort_keys=True)
    return True, payload, ""


def trusted_route_identity_from_assertion(env: dict[str, str], *, repo: str = "", issue: int | str = "", route: str = "") -> tuple[str, str, str]:
    expected = {"repo": repo, "issue": issue, "route": route} if repo or issue or route else None
    ok, payload, error = verify_trust_assertion(env, env.get("JOHN_LOMEIN_TRUST_ASSERTION", ""), purpose="route", expected=expected)
    if not ok:
        return TRUST_PUBLIC, "", f"route_trust_assertion_{error}"
    return normalize_trust_tier(payload.get("tier")), str(payload.get("actor") or "").strip(), ""


def trusted_owner_approval_from_assertion(env: dict[str, str], *, bundle_id: str, approval_text: str, bundle_digest: str = "") -> tuple[str, list[str]]:
    ok, payload, error = verify_trust_assertion(env, env.get("JOHN_LOMEIN_TRUST_ASSERTION", ""), purpose="release_approval")
    if not ok:
        return "", [f"approval_trust_assertion_{error}"]
    blockers: list[str] = []
    if str(payload.get("bundle_id") or "") != str(bundle_id):
        blockers.append("approval_trust_assertion_bundle_mismatch")
    if bundle_digest and str(payload.get("bundle_digest") or "") != str(bundle_digest):
        blockers.append("approval_trust_assertion_digest_mismatch")
    if not str(payload.get("nonce") or "").strip():
        blockers.append("approval_trust_assertion_missing_nonce")
    expected_hash = normalized_text_hash(approval_text)
    if str(payload.get("approval_hash") or "") != expected_hash:
        blockers.append("approval_trust_assertion_text_mismatch")
    tier = normalize_trust_tier(payload.get("tier"))
    if tier != TRUST_OWNER:
        blockers.append("approval_trust_assertion_not_owner")
    actor = str(payload.get("actor") or "").strip()
    blockers.extend(trusted_owner_approval_blockers(env, actor))
    return actor, blockers


def notification_meta(*, source: str, instance: str, repo: str, action_board: dict[str, Any]) -> dict[str, Any]:
    classes: list[str] = []
    if action_board.get(ACTION_OWNER):
        classes.append(ACTION_OWNER)
    if action_board.get(ACTION_AUTOMATION_BLOCKER):
        classes.append(ACTION_AUTOMATION_BLOCKER)
    should_notify = bool(classes)
    payload = {
        "source": source,
        "instance": instance,
        "repo": repo,
        "classes": classes,
        "owner": action_board.get(ACTION_OWNER) or {},
        "automation": action_board.get(ACTION_AUTOMATION_BLOCKER) or {},
    }
    return {
        "source": source,
        "classes": classes,
        "should_notify": should_notify,
        "fingerprint": stable_fingerprint(payload) if should_notify else "",
    }


def _pr_numbers(prs: list[dict]) -> list[int]:
    out: list[int] = []
    for pr in prs:
        try:
            out.append(int(pr.get("number") or 0))
        except Exception:
            pass
    return [n for n in out if n > 0]


def queue_action_board(
    *,
    clean_candidates: list[int],
    codex_pending_prs: list[int],
    codex_awaiting_prs: list[int],
    drafts: list[int],
    portfolio_owner_gated_prs: list[int],
    failures: list[str],
    alerts: list[str],
    untriaged_actionable_issues: list[int],
    triage_needed_issues: list[int],
    ignored_open_issues: list[int],
    blocked_forge_cycles: list[str],
) -> dict[str, Any]:
    owner: dict[str, Any] = {}
    automation: dict[str, Any] = {}
    codex_pending: dict[str, Any] = {}
    noise: dict[str, Any] = {}
    triage: dict[str, Any] = {}

    if clean_candidates:
        owner["clean_owner_gated_prs"] = sorted(clean_candidates)
    if portfolio_owner_gated_prs:
        owner["portfolio_owner_gated_prs"] = sorted(portfolio_owner_gated_prs)
    if untriaged_actionable_issues:
        triage["untriaged_actionable_issues"] = sorted(untriaged_actionable_issues)
    if triage_needed_issues:
        triage["triage_needed_issues"] = sorted(triage_needed_issues)
    if triage:
        owner[ACTION_TRIAGE] = triage
    if codex_pending_prs:
        codex_pending["prs"] = sorted(codex_pending_prs)
    if ignored_open_issues:
        noise["open_issues"] = sorted(ignored_open_issues)

    triage_prefixes = ("untriaged_actionable_issues=", "triage_needed_issues=")
    automation_alerts = [a for a in alerts if not a.startswith(triage_prefixes)]
    if failures:
        automation["failures"] = list(failures)
    if drafts:
        automation["draft_prs_needing_promotion_or_review"] = sorted(drafts)
    if codex_awaiting_prs:
        automation["codex_awaiting_prs"] = sorted(codex_awaiting_prs)
    if automation_alerts:
        automation["alerts"] = automation_alerts
    if blocked_forge_cycles:
        automation["blocked_forge_cycles"] = blocked_forge_cycles

    return {
        ACTION_OWNER: owner,
        ACTION_AUTOMATION_BLOCKER: automation,
        ACTION_CODEX_PENDING: codex_pending,
        ACTION_NOISE: noise,
    }


def release_bundle_action_board(*, bundle_id: str, clean_prs: list[dict], blockers: list[str]) -> dict[str, Any]:
    owner: dict[str, Any] = {}
    automation: dict[str, Any] = {}
    if clean_prs:
        owner["release_bundles"] = [{"bundle_id": bundle_id, "clean_prs": _pr_numbers(clean_prs)}]
    if blockers:
        automation["release_blockers"] = list(blockers)
    return {
        ACTION_OWNER: owner,
        ACTION_AUTOMATION_BLOCKER: automation,
        ACTION_CODEX_PENDING: {},
        ACTION_NOISE: {},
    }


def notification_seen(env: dict[str, str], label: str, fingerprint: str) -> bool:
    if not fingerprint:
        return True
    home = Path(env.get("BOT_HERMES_HOME") or env.get("HERMES_HOME") or "").expanduser()
    root = home / "state" / "notifications"
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{label.lower().replace('/', '_')}.fingerprint"
    previous = path.read_text(encoding="utf-8") if path.exists() else ""
    if previous == fingerprint:
        return True
    path.write_text(fingerprint, encoding="utf-8")
    return False


def normalize_trust_tier(value: object) -> str:
    tier = str(value or TRUST_PUBLIC).strip().lower().replace("-", "_")
    if tier == "trusted_owner":
        tier = TRUST_OWNER
    if tier == "trusted_collaborator":
        tier = TRUST_COLLABORATOR
    if tier not in TRUST_TIERS:
        return TRUST_UNTRUSTED
    return tier


def route_allowed_for_trust(tier: str) -> bool:
    return normalize_trust_tier(tier) in {TRUST_OWNER, TRUST_COLLABORATOR}


def configured_owner_approvers(env: dict[str, str]) -> list[str]:
    raw = (
        env.get("BOT_OWNER_APPROVERS")
        or env.get("BOT_DISCORD_OWNER_USER_IDS")
        or ""
    )
    return split_csv(raw)


def trusted_owner_approval_blockers(env: dict[str, str], approver: str) -> list[str]:
    approver = (approver or "").strip()
    owners = configured_owner_approvers(env)
    if not approver:
        return ["approval_trusted_owner_identity_missing"]
    if not owners:
        return ["approval_trusted_owner_registry_missing"]
    if approver not in owners:
        return ["approval_actor_not_trusted_owner"]
    return []
