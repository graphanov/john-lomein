#!/usr/bin/env python3
"""Run a deterministic, read-only maintainer-factory simulation."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, is_dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable

sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import john_lomein_factory_receipts as receipts


SCENARIO = "roadmap-maintainer"
SIMULATION_TIME = 1_767_225_600.0
WORK_PACKET_SCHEMA = "john-lomein.factory-work-packet.v1"
OWNER_GATED_ACTIONS = ["merge", "publish", "release", "workflow dispatch"]
SIMULATION_CONTRACT_AUTHORITY = "john-lomein-simulation-contract-checker"
ARTIFACT_NAMES = [
    "work-packet.json",
    "triage-receipt.json",
    "false-green-receipt.json",
    "synthetic-contract-receipt.json",
    "simulation-result.json",
]
AMENDMENT_RE = re.compile(r"^(?P<parent>.+)-amendment-(?P<number>[1-9][0-9]*)$")
SAFE_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$", re.IGNORECASE)
ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9:/<])/(?!/)[^\s,;:`'\"<>]+")


class SimulationError(Exception):
    """A public-safe simulation failure with a stable machine code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _load_portfolio_steward() -> ModuleType:
    """Dynamically load the existing portfolio detector without running its CLI."""
    path = SCRIPT_DIR / "john-lomein-osc-portfolio-steward.py"
    spec = importlib.util.spec_from_file_location("_john_lomein_factory_simulation_portfolio", path)
    if spec is None or spec.loader is None:
        raise SimulationError("portfolio_detector_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise SimulationError("portfolio_detector_unavailable") from exc
    if not callable(getattr(module, "detect_gaps", None)):
        raise SimulationError("portfolio_detector_unavailable")
    return module


def _load_queue_health() -> ModuleType:
    """Load the production queue projection without invoking its CLI or GitHub."""
    path = SCRIPT_DIR / "john-lomein-queue-health.py"
    spec = importlib.util.spec_from_file_location("_john_lomein_factory_simulation_queue", path)
    if spec is None or spec.loader is None:
        raise SimulationError("queue_projection_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise SimulationError("queue_projection_unavailable") from exc
    if not callable(getattr(module, "reconcile_receipt_summaries", None)) or not callable(
        getattr(module, "factory_loop_view", None)
    ):
        raise SimulationError("queue_projection_unavailable")
    return module


def _trusted_git() -> Path:
    candidates = (
        Path("/Applications/Xcode.app/Contents/Developer/usr/bin/git"),
        Path("/Library/Developer/CommandLineTools/usr/bin/git"),
        Path("/usr/bin/git"),
    )
    git = next((candidate for candidate in candidates if candidate.is_file()), None)
    if git is None:
        raise SimulationError("repo_git_unavailable")
    return git


def _git_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/var/empty",
        "TMPDIR": "/var/empty",
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
    }


def _git_sandbox_profile(repo: Path) -> str:
    dot_git = repo / ".git"
    if not dot_git.is_dir() or dot_git.is_symlink():
        raise SimulationError("repo_git_layout_unsafe")
    resolved_repo = repo.resolve(strict=True)
    protected = {
        Path("/Users").resolve(strict=False),
        Path("/private/tmp").resolve(strict=False),
        Path(tempfile.gettempdir()).resolve(strict=False),
    }
    metadata_ancestors: set[Path] = set()
    for protected_root in protected:
        if not resolved_repo.is_relative_to(protected_root):
            continue
        current = resolved_repo.parent
        while current.is_relative_to(protected_root):
            metadata_ancestors.add(current)
            if current == protected_root:
                break
            current = current.parent
    deny_reads = "\n".join(f"  (subpath {json.dumps(str(path))})" for path in sorted(protected, key=str))
    metadata_reads = "\n".join(
        f"  (literal {json.dumps(str(path))})" for path in sorted(metadata_ancestors, key=str)
    )
    metadata_block = f"(allow file-read-metadata\n{metadata_reads})\n" if metadata_reads else ""
    return f"""(version 1)
(allow default)
(deny network*)
(deny appleevent-send)
(deny process-info*)
(allow process-info* (target self))
(deny process-exec
  (require-not
    (require-any
      (literal "/usr/bin/git")
      (literal "/Applications/Xcode.app/Contents/Developer/usr/bin/git")
      (literal "/Library/Developer/CommandLineTools/usr/bin/git")
      (subpath "/Applications/Xcode.app/Contents/Developer/usr/libexec/git-core")
      (subpath "/Library/Developer/CommandLineTools/usr/libexec/git-core")
      (subpath "/usr/libexec/git-core"))))
(deny file-read*
{deny_reads})
{metadata_block}(allow file-read*
  (subpath {json.dumps(str(resolved_repo))}))
(deny file-write*)
(allow file-write* (literal "/dev/null"))
"""


def _git_sandbox_available() -> bool:
    return sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file()


def _run_git(repo: Path, args: list[str]) -> str:
    git = _trusted_git()
    command = [
        str(git),
        "--no-optional-locks",
        "-c", "core.fsmonitor=false",
        "-c", "core.untrackedCache=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", "credential.helper=",
        "-c", "core.pager=cat",
        "-c", "pager.status=false",
        "-c", "diff.external=",
        "-c", "interactive.diffFilter=",
        "-c", "submodule.recurse=false",
        "-C", str(repo),
        *args,
    ]
    if _git_sandbox_available():
        command = ["/usr/bin/sandbox-exec", "-p", _git_sandbox_profile(repo), *command]
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            env=_git_env(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SimulationError("repo_git_read_failed") from exc
    if proc.returncode != 0:
        raise SimulationError("repo_git_read_failed")
    return proc.stdout.strip()


def read_repo_seed(repo: Path) -> dict[str, Any]:
    """Read only public-safe branch, commit, and dirty facts from a checkout."""
    head_sha = _run_git(repo, ["rev-parse", "--verify", "HEAD^{commit}"])
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", head_sha):
        raise SimulationError("repo_head_invalid")
    try:
        branch = _run_git(repo, ["symbolic-ref", "--short", "-q", "HEAD"])
    except SimulationError:
        branch = "detached"
    if _git_sandbox_available():
        dirty = bool(_run_git(repo, ["status", "--porcelain=v1", "--untracked-files=normal"]))
        dirty_probe = "sandboxed_git_status"
    else:
        dirty = True
        dirty_probe = "conservative_without_git_sandbox"
    seed = {
        "branch": str(receipts.redact_public(branch or "detached")),
        "head_sha": head_sha.lower(),
        "dirty": dirty,
        "source": "read_only_git",
        "optional_locks": False,
        "dirty_probe": dirty_probe,
    }
    ensure_public_payload(seed)
    return seed


def read_instance_seed(instance: Path) -> dict[str, Any]:
    """Read only a conservative, public subset of the instance manifest."""
    manifest = instance / "instance.yaml"
    slug = "configured"
    if manifest.is_file() and not manifest.is_symlink():
        in_instance = False
        for raw in manifest.read_text(encoding="utf-8", errors="ignore").splitlines():
            if raw and not raw.startswith((" ", "\t")):
                in_instance = raw.strip() == "instance:"
                continue
            if in_instance:
                match = re.match(r"^\s{2,}slug:\s*['\"]?([^'\"#\s]+)", raw)
                if match:
                    candidate = match.group(1)
                    if SAFE_SLUG_RE.fullmatch(candidate):
                        slug = candidate
                    break
    seed = {
        "slug": str(receipts.redact_public(slug)),
        "manifest_present": manifest.is_file() and not manifest.is_symlink(),
        "access": "read_only",
        "private_runtime_inputs_read": False,
    }
    ensure_public_payload(seed)
    return seed


def read_mission_summary(repo: Path) -> dict[str, str]:
    """Read a concise mission heading and first substantive paragraph."""
    mission = repo / "MISSION.md"
    fallback = {
        "source": "generic_fallback",
        "title": "Repository mission",
        "summary": "Maintain repository plans through evidence-bound, owner-gated work.",
    }
    if not mission.is_file() or mission.is_symlink():
        return fallback
    try:
        mission.resolve().relative_to(repo.resolve())
    except ValueError as exc:
        raise SimulationError("mission_path_unsafe") from exc
    lines = mission.read_text(encoding="utf-8", errors="ignore").splitlines()
    title = next((line[2:].strip() for line in lines if line.startswith("# ") and line[2:].strip()), "Mission")
    paragraph_lines: list[str] = []
    after_title = False
    for line in lines:
        stripped = line.strip()
        if not after_title:
            if line.startswith("# "):
                after_title = True
            continue
        if not stripped:
            if paragraph_lines:
                break
            continue
        if stripped.startswith(("#", "<!--", "```", "- ", "* ")):
            if paragraph_lines:
                break
            continue
        paragraph_lines.append(stripped)
    if not paragraph_lines:
        return fallback
    summary = {
        "source": "MISSION.md",
        "title": title[:120],
        "summary": " ".join(paragraph_lines)[:600],
    }
    summary = receipts.redact_public(summary)
    ensure_public_payload(summary)
    return summary


def _candidate_dict(candidate: Any) -> dict[str, Any]:
    raw = asdict(candidate) if is_dataclass(candidate) else dict(getattr(candidate, "__dict__", {}))
    projected = {
        "gap_id": str(raw.get("gap_id") or "unknown"),
        "kind": str(raw.get("kind") or "unknown"),
        "title": str(raw.get("title") or "")[:240],
        "summary": str(raw.get("summary") or "")[:500],
        "evidence": [str(item)[:500] for item in (raw.get("evidence") or [])],
        "confidence": str(raw.get("confidence") or "unknown"),
        "proposed_plan_slug": str(raw.get("proposed_plan_slug") or "follow-up")[:96],
        "source_paths": [str(item) for item in (raw.get("source_paths") or [])],
    }
    projected = receipts.redact_public(projected)
    ensure_public_payload(projected)
    return projected


def detect_portfolio_candidates(repo: Path) -> list[dict[str, Any]]:
    detector = _load_portfolio_steward()
    try:
        candidates = detector.detect_gaps(repo)
    except Exception as exc:
        raise SimulationError("portfolio_scan_failed") from exc
    return [_candidate_dict(candidate) for candidate in candidates]


def detect_active_amendment_ambiguity(repo: Path) -> list[dict[str, str]]:
    """Find active amendment files whose parent plan is still active."""
    active = repo / ".osc" / "plans" / "active"
    if not active.is_dir() or active.is_symlink():
        return []
    names = {
        path.stem: path
        for path in active.glob("*.md")
        if path.is_file() and not path.is_symlink()
    }
    ambiguities: list[dict[str, str]] = []
    for stem, amendment in sorted(names.items()):
        match = AMENDMENT_RE.fullmatch(stem)
        if not match or match.group("parent") not in names:
            continue
        parent = names[match.group("parent")]
        ambiguities.append(
            {
                "kind": "active_parent_and_amendment",
                "parent": parent.relative_to(repo).as_posix(),
                "amendment": amendment.relative_to(repo).as_posix(),
                "route": "triage",
            }
        )
    ensure_public_payload(ambiguities)
    return ambiguities


def choose_candidate(candidates: Iterable[dict[str, Any]]) -> dict[str, Any]:
    ordered = list(candidates)
    if not ordered:
        raise SimulationError("portfolio_candidate_missing")
    folded = [item for item in ordered if item.get("kind") == "folded_backlog_unreconciled"]
    return dict(folded[0] if folded else ordered[0])


def ensure_public_payload(payload: Any) -> None:
    redacted = receipts.redact_public(payload)
    if redacted != payload or not receipts.public_safe(payload):
        raise SimulationError("public_projection_failed")

    def strings(value: Any) -> Iterable[str]:
        if isinstance(value, dict):
            for key, child in value.items():
                yield str(key)
                yield from strings(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                yield from strings(child)
        elif isinstance(value, str):
            yield value

    if any(ABSOLUTE_PATH_RE.search(value) for value in strings(payload)):
        raise SimulationError("absolute_path_in_public_projection")


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def validate_inputs(instance: Path, repo: Path, output_dir: Path | None) -> tuple[Path, Path, Path | None]:
    instance = instance.expanduser().resolve()
    repo = repo.expanduser().resolve()
    if not instance.is_dir():
        raise SimulationError("instance_missing")
    if not repo.is_dir() or not (repo / ".osc" / "plans").is_dir():
        raise SimulationError("repo_portfolio_missing")
    if output_dir is None:
        return instance, repo, None
    output = output_dir.expanduser().resolve()
    if _paths_overlap(output, repo) or _paths_overlap(output, instance):
        raise SimulationError("output_dir_overlaps_inputs")
    if output.exists() and (not output.is_dir() or output.is_symlink()):
        raise SimulationError("output_dir_unsafe")
    return instance, repo, output


def _receipt_verifier(verdict: dict[str, Any]) -> dict[str, Any]:
    return {
        "verdict": str(verdict.get("verdict") or "blocked"),
        "checks": list(verdict.get("checks") or []),
        "missing": list(verdict.get("missing") or []),
    }


def build_simulation(instance: Path, repo: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    repo_seed = read_repo_seed(repo)
    instance_seed = read_instance_seed(instance)
    mission_summary = read_mission_summary(repo)
    candidates = detect_portfolio_candidates(repo)
    selected = choose_candidate(candidates)
    ambiguities = detect_active_amendment_ambiguity(repo)
    intake_classification = "triage" if ambiguities else "roadmap_candidate"
    intake_route = "triage" if ambiguities else "roadmap_portfolio"

    stable_seed = {
        "scenario": SCENARIO,
        "repo": repo_seed,
        "instance": instance_seed,
        "mission_summary": mission_summary,
        "candidate_ids": [item["gap_id"] for item in candidates],
        "ambiguities": ambiguities,
    }
    run_id = "simulation-" + receipts.stable_hash(stable_seed)[:12]
    expected_branch = "portfolio/" + selected["proposed_plan_slug"]
    proposed_file = ".osc/plans/backlog/" + selected["proposed_plan_slug"] + ".md"
    packet_id = "packet-" + receipts.stable_hash(
        {"run_id": run_id, "gap_id": selected["gap_id"], "branch": expected_branch}
    )[:12]
    event = {
        "kind": "owner_like_roadmap_signal",
        "id": "roadmap-maintainer-simulation",
        "source": "read_only_repository_portfolio",
        "authority": "synthetic_fixture_no_live_authority",
        "content_trust": "repository_data",
        "summary": "Audit the current plan portfolio and propose one evidence-bound maintenance packet.",
    }
    intake = {
        "classification": intake_classification,
        "route": intake_route,
        "mission_fit": "high",
        "ambiguity": "high" if ambiguities else "low",
        "active_plan_ambiguities": ambiguities,
        "public_input_is_authority": False,
        "owner_question": (
            "Which active plan record is authoritative before portfolio reconciliation proceeds?"
            if ambiguities
            else ""
        ),
        "live_execution_allowed": False,
        "contract_exercise_continues_synthetically": True,
    }
    ambiguity_gate = {
        "live_path": {
            "loop": "triage" if ambiguities else "roadmap_portfolio",
            "classification": intake_classification,
            "state": "held_for_owner_clarification" if ambiguities else "read_only_proposal_only",
            "execution_allowed": False,
        },
        "contract_exercise_path": {
            "mode": "counterfactual_after_synthetic_clarification" if ambiguities else "synthetic_read_only",
            "authority_granted": False,
            "purpose": "exercise_verifier_queue_and_owner_gate_contracts",
        },
    }
    work_packet = {
        "schema_version": WORK_PACKET_SCHEMA,
        "packet_id": packet_id,
        "scenario": SCENARIO,
        "mode": "proposed_read_only_simulation",
        "status": "counterfactual_contract_exercise_after_triage" if ambiguities else "proposed_read_only",
        "event": event,
        "mission_summary": mission_summary,
        "selected_candidate": selected,
        "expected_branch": expected_branch,
        "plan": {
            "intent": "Reconcile one folded backlog record through a reviewable plan change.",
            "proposed_file": proposed_file,
            "constraints": [
                "no_repository_or_instance_mutation",
                "no_remote_calls",
                "verifier_owns_completion",
                "owner_gate_required_for_unsafe_actions",
            ],
            "verification": [
                "relative_changed_file_present",
                "synthetic_branch_and_head_match",
                "synthetic_configured_test_passes",
            ],
        },
        "authority": {
            "executor_can_mark_done": False,
            "done_authority": receipts.DONE_AUTHORITY,
            "owner_gated_actions": OWNER_GATED_ACTIONS,
            "live_triage_bypass_allowed": False,
            "synthetic_evidence_grants_live_authority": False,
        },
    }

    triage_receipt = receipts.create_receipt(
        run_id=run_id + "-triage",
        event=event,
        loop="intake",
        phase="ambiguity_classified" if ambiguities else "mission_fit_classified",
        classification=intake_classification,
        evidence={
            "work_packet_id": packet_id,
            "mission_summary": mission_summary,
            "active_plan_ambiguities": ambiguities,
            "portfolio_candidate_count": len(candidates),
        },
        executor_report={"status": "NOT_RUN", "exit_code": None, "status_source": "simulation_intake"},
        verifier={
            "verdict": "passed",
            "checks": [
                {
                    "name": "ambiguity_routed_before_live_execution",
                    "passed": True,
                    "evidence": f"route={intake_route}",
                }
            ],
            "missing": [],
        },
        next_action={
            "class": "owner_action" if ambiguities else "automation",
            "action": "clarify_active_plan_authority" if ambiguities else "prepare_proposed_packet",
        },
        mission={
            "statement": mission_summary["summary"],
            "source": mission_summary["source"],
            "creative_posture": "propose_bounded_roadmap_work",
        },
        now=SIMULATION_TIME,
    )

    executor_report = {
        "status": "COMPLETE",
        "exit_code": 0,
        "status_source": "synthetic_executor_report",
    }
    false_evidence = {
        "expected_branch": expected_branch,
        "pr": {},
        "worktree": {},
        "verification": {},
        "provenance": "synthetic_missing_evidence",
    }
    false_verdict = receipts.completion_verdict(
        executor_report=executor_report,
        evidence=false_evidence,
    )
    false_green_receipt = receipts.create_receipt(
        run_id=run_id + "-implementation",
        event={
            "kind": "simulated_implementation",
            "id": packet_id,
            "source": "factory_simulation",
            "authority": "none",
            "content_trust": "synthetic",
            "summary": "Challenge an executor completion claim with independent evidence checks.",
        },
        loop="ci_repair",
        phase="verifier_blocked",
        classification="repair_due",
        evidence={
            "work_packet_id": packet_id,
            "branch": expected_branch,
            "evidence_provenance": "synthetic_missing_evidence",
        },
        executor_report=executor_report,
        verifier=_receipt_verifier(false_verdict),
        next_action={"class": "automation", "action": "collect_independent_verifier_evidence"},
        now=SIMULATION_TIME,
    )

    synthetic_head = receipts.stable_hash(
        {"packet_id": packet_id, "base_head": repo_seed["head_sha"], "kind": "synthetic_head"}
    )[:40]
    verified_evidence = {
        "expected_branch": expected_branch,
        "files": [proposed_file],
        "pr": {
            "open": True,
            "branch": expected_branch,
            "draft": True,
            "issue_link": True,
            "head_sha": synthetic_head,
        },
        "worktree": {
            "isolated": True,
            "branch": expected_branch,
            "head_sha": synthetic_head,
            "clean": True,
        },
        "verification": {
            "diff_check_exit_code": 0,
            "configured_test": True,
            "test_exit_code": 0,
            "head_stable_during_test": True,
            "sandbox_enforced": True,
        },
        "provenance": "explicitly_synthetic_simulation_evidence",
        "commands_executed": False,
        "remote_calls": 0,
    }
    verified_verdict = receipts.completion_verdict(
        executor_report=executor_report,
        evidence=verified_evidence,
    )
    if false_verdict.get("verdict") != "blocked" or not false_verdict.get("missing"):
        raise SimulationError("false_green_guard_failed")
    structural_missing = [
        name for name in (verified_verdict.get("missing") or []) if name != "live_verifier_evidence"
    ]
    if verified_verdict.get("verdict") != "blocked" or structural_missing:
        raise SimulationError("synthetic_contract_exercise_failed")
    verified_verdict["checks"].append(
        {
            "name": "codex_review_handoff_recorded",
            "passed": True,
            "evidence": "synthetic_handoff_only",
        }
    )

    synthetic_contract_receipt = receipts.update_receipt(
        false_green_receipt,
        loop="ci_repair",
        phase="synthetic_contract_checked_live_evidence_missing",
        classification="repair_due",
        evidence={
            "head_sha": synthetic_head,
            "files": [proposed_file],
            "evidence_provenance": "explicitly_synthetic_simulation_evidence",
            "verifier_provenance": "explicitly_synthetic_simulation_evidence",
            "commands_executed": False,
            "remote_calls": 0,
            "unsafe_actions_blocked": OWNER_GATED_ACTIONS,
            "contract_authority": SIMULATION_CONTRACT_AUTHORITY,
        },
        verifier=_receipt_verifier(verified_verdict),
        next_action={"class": "automation", "action": "collect_live_verifier_evidence"},
        now=SIMULATION_TIME,
    )

    receipt_list = [triage_receipt, false_green_receipt, synthetic_contract_receipt]
    summaries = [receipts.public_summary(item) for item in receipt_list]
    latest_by_event: dict[tuple[str, str], dict[str, Any]] = {}
    for summary in summaries:
        event_summary = dict(summary.get("event") or {})
        event_key = (
            str(event_summary.get("kind") or "unknown"),
            str(event_summary.get("id") or summary.get("run_id") or "unknown"),
        )
        latest_by_event[event_key] = summary
    queue_health_module = _load_queue_health()
    reconciled_summaries = queue_health_module.reconcile_receipt_summaries(
        list(latest_by_event.values()),
        open_issue_numbers=set(),
        open_pr_details=[],
        codex_pending_prs=[],
    )
    factory_loops = queue_health_module.factory_loop_view(
        {},
        receipt_summaries=reconciled_summaries,
        roadmap_candidates=candidates,
    )
    owner_gate = {
        "required": True,
        "scope": "simulation_only_contract",
        "state": "blocked_pending_explicit_owner_approval",
        "production_queue_classification": "repair_due",
        "blocked_actions": OWNER_GATED_ACTIONS,
        "executed_actions": [],
        "reviewable_packet_id": packet_id,
    }
    feedback = {
        "learning": [
            {
                "observation": "Executor COMPLETE with exit zero is insufficient without independent evidence.",
                "route": "verifier_policy",
                "status": "captured_in_simulation_receipt",
            }
        ],
        "roadmap": {
            "selected_gap_id": selected["gap_id"],
            "selected_kind": selected["kind"],
            "selection_policy": "prefer_folded_backlog_unreconciled",
            "next_action": "owner_review_after_active_plan_triage" if ambiguities else "owner_review",
        },
    }
    result = {
        "schema_version": receipts.SIMULATION_SCHEMA,
        "scenario": SCENARIO,
        "mode": "read_only_dry_run",
        "result": "pass",
        "events_processed": [event["id"], packet_id],
        "inputs": {
            "repo_seed": repo_seed,
            "instance_seed": instance_seed,
            "mission_summary": mission_summary,
        },
        "ambiguity_gate": ambiguity_gate,
        "repo_seed": repo_seed,
        "instance_seed": instance_seed,
        "intake": intake,
        "portfolio_candidates": candidates,
        "selected_candidate": selected,
        "work_packet": work_packet,
        "false_green_guard": {
            "classification": "repair_due",
            "executor_report": executor_report,
            "verifier_verdict": false_verdict["verdict"],
            "missing_checks": list(false_verdict["missing"]),
            "contract_exercised": True,
        },
        "synthetic_contract_assessment": {
            "classification": "simulation_only_owner_gate",
            "authority": SIMULATION_CONTRACT_AUTHORITY,
            "evidence_provenance": "explicitly_synthetic_simulation_evidence",
            "files": [proposed_file],
            "remote_calls": 0,
            "contract_status": "exercised",
            "production_completion_verdict": verified_verdict["verdict"],
            "structural_missing_checks": structural_missing,
            "missing_live_requirements": list(verified_verdict["missing"]),
            "contract_exercised": True,
        },
        "receipts": receipt_list,
        "factory_loops": factory_loops,
        "queue_health": {
            "projection_source": "production_queue_health_functions",
            "receipt_count": len(reconciled_summaries),
            "historical_receipt_count": len(receipt_list),
            "factory_loops": factory_loops,
        },
        "final_state": {
            "live_path": ambiguity_gate["live_path"],
            "contract_exercise_path": {
                "loop": "owner_gate",
                "classification": "simulation_only_owner_gate",
                "contract_status": "exercised",
                "production_completion_verdict": verified_verdict["verdict"],
                "production_queue_classification": "repair_due",
                "synthetic_only": True,
            },
        },
        "owner_gate": owner_gate,
        "unsafe_actions_blocked": OWNER_GATED_ACTIONS,
        "feedback": feedback,
        "mutation_summary": {
            "repo_mutations": 0,
            "instance_mutations": 0,
            "remote_calls": 0,
            "synthetic_only": True,
        },
        "artifacts": [],
    }
    artifacts = {
        "work-packet.json": work_packet,
        "triage-receipt.json": triage_receipt,
        "false-green-receipt.json": false_green_receipt,
        "synthetic-contract-receipt.json": synthetic_contract_receipt,
    }
    ensure_public_payload(result)
    return result, artifacts


def persist_artifacts(output_dir: Path, result: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    if output_dir.is_symlink():
        raise SimulationError("output_dir_unsafe")
    for name in ARTIFACT_NAMES[:-1]:
        payload = artifacts[name]
        if name.endswith("receipt.json"):
            receipts.write_receipt(output_dir / name, payload)
        else:
            receipts.atomic_write_json(output_dir / name, payload)
    receipts.atomic_write_json(output_dir / ARTIFACT_NAMES[-1], result)


def simulate(
    *,
    instance: Path,
    repo: Path,
    scenario: str = SCENARIO,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    if scenario != SCENARIO:
        raise SimulationError("unsupported_scenario")
    instance, repo, output = validate_inputs(instance, repo, output_dir)
    result, artifacts = build_simulation(instance, repo)
    if output is not None:
        result["artifacts"] = list(ARTIFACT_NAMES)
        ensure_public_payload(result)
        persist_artifacts(output, result, artifacts)
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a deterministic read-only factory simulation.")
    parser.add_argument("--instance", required=True, type=Path)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--scenario", required=True, choices=[SCENARIO])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    if not args.dry_run:
        parser.error("--dry-run is required; this harness has no mutation mode")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = simulate(
            instance=args.instance,
            repo=args.repo,
            scenario=args.scenario,
            output_dir=args.output_dir,
        )
    except SimulationError as exc:
        error = {"schema_version": receipts.SIMULATION_SCHEMA, "result": "error", "error": exc.code}
        if args.json_output:
            print(json.dumps(error, sort_keys=True, separators=(",", ":")))
        else:
            print(f"factory simulation error: {exc.code}", file=sys.stderr)
        return 2
    except Exception:
        error = {"schema_version": receipts.SIMULATION_SCHEMA, "result": "error", "error": "simulation_failed"}
        if args.json_output:
            print(json.dumps(error, sort_keys=True, separators=(",", ":")))
        else:
            print("factory simulation error: simulation_failed", file=sys.stderr)
        return 2
    if args.json_output:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(
            f"factory simulation {result['result']}: "
            f"scenario={result['scenario']} "
            f"contract_loop={result['final_state']['contract_exercise_path']['loop']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
