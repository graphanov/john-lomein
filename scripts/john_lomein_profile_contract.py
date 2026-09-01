#!/usr/bin/env python3
"""Canonical John Lomein role/profile bindings.

Profiles are product-owned execution identities. Instance manifests may repeat
the shipped values for readability, but they cannot rename roles, permute
profiles, or introduce additional filesystem path components.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

CANONICAL_ROLE_PROFILES: dict[str, str] = {
    "maintainer": "john-lomein-maintainer",
    "forge": "john-lomein-forge",
    "guide": "john-lomein-guide",
    "overwatch": "john-lomein-overwatch",
    "learning_steward": "john-lomein-learning-steward",
}

ROLE_PROFILE_ENV_KEYS: dict[str, str] = {
    role: f"BOT_{role.upper()}_PROFILE"
    for role in CANONICAL_ROLE_PROFILES
}


def _mapping(value: Any, *, field: str) -> Mapping[str, Any]:
    if value in (None, ""):
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"unsafe {field}: expected mapping")
    return value


def _exact_profile(value: Any, *, field: str, expected: str) -> str:
    if value in (None, ""):
        return expected
    if not isinstance(value, str) or value != expected:
        raise ValueError(f"unsafe {field}: expected {expected}")
    return value


def canonical_role_profiles(manifest: Mapping[str, Any]) -> dict[str, str]:
    """Return the exact product role map or reject the manifest.

    ``learning.steward_profile`` is a legacy compatibility spelling. When
    present it is validated even if ``profiles.learning_steward`` is also set,
    so a hidden conflicting value cannot survive into another consumer.
    """
    if not isinstance(manifest, Mapping):
        raise ValueError("unsafe instance manifest: expected mapping")
    profiles = _mapping(manifest.get("profiles"), field="profiles")
    learning = _mapping(manifest.get("learning"), field="learning")

    resolved: dict[str, str] = {}
    for role, expected in CANONICAL_ROLE_PROFILES.items():
        resolved[role] = _exact_profile(
            profiles.get(role),
            field=f"profiles.{role}",
            expected=expected,
        )

    legacy_steward = learning.get("steward_profile")
    _exact_profile(
        legacy_steward,
        field="learning.steward_profile",
        expected=CANONICAL_ROLE_PROFILES["learning_steward"],
    )
    return resolved


def canonical_profile_name(value: Any, *, field: str = "profile") -> str:
    if not isinstance(value, str) or value not in CANONICAL_ROLE_PROFILES.values():
        raise ValueError(f"unsafe {field}: expected canonical John Lomein profile")
    return value


def validate_profile_env(
    env: Mapping[str, Any],
    *,
    expected_profiles: Mapping[str, str] | None = None,
) -> None:
    """Reject configured runtime env profile identities that drift from product."""
    expected_profiles = expected_profiles or CANONICAL_ROLE_PROFILES
    for role, expected in expected_profiles.items():
        key = ROLE_PROFILE_ENV_KEYS[role]
        raw = env.get(key)
        if raw not in (None, "") and raw != expected:
            raise ValueError(f"unsafe {key}: expected {expected}")
