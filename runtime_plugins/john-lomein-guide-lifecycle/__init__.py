from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import threading
from collections import OrderedDict
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import yaml

RUNTIME_HOME = Path(__file__).resolve().parents[2]
SCRIPTS = RUNTIME_HOME / "scripts"
PAUSE_FILE = RUNTIME_HOME / "state" / "honcho" / "INGESTION_PAUSED.json"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from john_lomein_guide_lifecycle import (  # noqa: E402
    DEFAULT_GUIDE_DIALOGUE_POLICY,
    GUIDE_MEMORY_PAUSED_OUTPUT,
    GUIDE_OUTPUT_BLOCKED,
    GUIDE_PROFILE,
    dialogue_signals,
    enforce_guide_output,
    fail_closed_context,
    guide_dialogue_policy,
    render_lifecycle_context,
)

_MAX_TURN_STATES = 256
_TURN_STATES: OrderedDict[str, tuple[int, dict[str, Any], dict[str, Any]]] = OrderedDict()
_TURN_SEQUENCE: dict[str, int] = {}
_TURN_STATES_LOCK = threading.RLock()


def _begin_turn(session_id: str) -> int:
    key = str(session_id or "").strip()
    if not key:
        return 0
    with _TURN_STATES_LOCK:
        token = _TURN_SEQUENCE.get(key, 0) + 1
        _TURN_SEQUENCE[key] = token
        _TURN_STATES.pop(key, None)
        return token


def _remember_turn_state(
    session_id: str,
    turn_token: int,
    policy: Mapping[str, Any],
    signals: Mapping[str, Any],
) -> None:
    key = str(session_id or "").strip()
    if not key:
        return
    with _TURN_STATES_LOCK:
        if turn_token <= 0 or _TURN_SEQUENCE.get(key) != turn_token:
            return
        _TURN_STATES[key] = (turn_token, dict(policy), dict(signals))
        _TURN_STATES.move_to_end(key)
        while len(_TURN_STATES) > _MAX_TURN_STATES:
            _TURN_STATES.popitem(last=False)


def _consume_turn_state(session_id: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    key = str(session_id or "").strip()
    if not key:
        return None
    with _TURN_STATES_LOCK:
        state = _TURN_STATES.pop(key, None)
        if state is None or state[0] != _TURN_SEQUENCE.get(key):
            return None
        return state[1], state[2]


def _clear_turn_states_for_test() -> None:
    with _TURN_STATES_LOCK:
        _TURN_STATES.clear()
        _TURN_SEQUENCE.clear()


def load_ingestion_pause(path: Path = PAUSE_FILE) -> dict[str, Any]:
    target = Path(path)
    if not target.exists():
        return {"active": False, "reasons": []}
    try:
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode) or target.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("unsafe pause receipt")
        payload = json.loads(target.read_text(encoding="utf-8"))
        unsigned = dict(payload)
        digest = unsigned.pop("receipt_digest", "")
        actual = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        if payload.get("schema_version") != "john-lomein.honcho-pause.v1" or payload.get("manual_clear_required") is not True or digest != actual:
            raise ValueError("invalid pause receipt")
        return {"active": True, "reasons": list(payload.get("reasons") or [])}
    except Exception:
        return {"active": True, "reasons": ["pause_receipt_invalid"]}


def load_runtime_manifest() -> Mapping[str, Any]:
    path = RUNTIME_HOME / "instance.yaml"
    if not path.exists():
        return {}
    if path.is_symlink() or not path.is_file():
        raise ValueError("unsafe Guide lifecycle manifest path")
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, Mapping):
        raise ValueError("unsafe Guide lifecycle manifest: expected mapping")
    return loaded


def _default_session_getter(name: str, default: str = "") -> str:
    from gateway.session_context import get_session_env

    return get_session_env(name, default)


def process_guide_lifecycle(
    *,
    user_message: str,
    conversation_history: Any,
    session_id: str = "",
    turn_token: int | None = None,
    session_getter: Callable[[str, str], str] | None = None,
    manifest_loader: Callable[[], Mapping[str, Any]] | None = None,
    pause_loader: Callable[[], Mapping[str, Any]] | None = None,
) -> dict[str, str] | None:
    if session_getter is None:
        session_getter = _default_session_getter
    if session_getter("HERMES_SESSION_PROFILE", "") != GUIDE_PROFILE:
        return None
    if manifest_loader is None:
        manifest_loader = load_runtime_manifest
    if turn_token is None:
        turn_token = _begin_turn(session_id)
    policy = guide_dialogue_policy(manifest_loader())
    signals = dialogue_signals(conversation_history, user_message, policy)
    pause = (pause_loader or load_ingestion_pause)()
    if pause.get("active") is True:
        signals.update({
            "stage": "INGESTION_PAUSED",
            "hard_stop": True,
            "questioning_permitted": False,
            "ingestion_paused": True,
            "stop_reasons": list(pause.get("reasons") or ["memory_unhealthy"]),
        })
    _remember_turn_state(session_id, int(turn_token or 0), policy, signals)
    return {"context": render_lifecycle_context(policy, signals)}


def pre_llm_call(**kwargs: Any) -> dict[str, str] | None:
    session_id = str(kwargs.get("session_id") or "")
    turn_token = _begin_turn(session_id)
    try:
        return process_guide_lifecycle(
            user_message=str(kwargs.get("user_message") or ""),
            conversation_history=kwargs.get("conversation_history") or [],
            session_id=session_id,
            turn_token=turn_token,
        )
    except Exception:
        _remember_turn_state(
            session_id,
            turn_token,
            DEFAULT_GUIDE_DIALOGUE_POLICY,
            {
                "stage": "EXHAUSTED",
                "hard_stop": True,
                "questioning_permitted": False,
                "stop_reasons": ["policy_unavailable"],
            },
        )
        return {"context": fail_closed_context()}


def transform_llm_output(**kwargs: Any) -> str | None:
    try:
        if _default_session_getter("HERMES_SESSION_PROFILE", "") != GUIDE_PROFILE:
            return None
        state = _consume_turn_state(str(kwargs.get("session_id") or ""))
        if state is None:
            return GUIDE_OUTPUT_BLOCKED
        policy, signals = state
        return enforce_guide_output(kwargs.get("response_text"), policy, signals)
    except Exception:
        return GUIDE_OUTPUT_BLOCKED


def register(ctx: Any) -> None:
    ctx.register_hook("pre_llm_call", pre_llm_call)
    ctx.register_hook("transform_llm_output", transform_llm_output)
