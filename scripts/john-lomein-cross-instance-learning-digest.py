#!/usr/bin/env python3
"""Cross-instance john-lomein learning digest.

Reads derived learning-steward reports from local john-lomein runtimes and writes
a compact markdown digest. Canonical truth remains in each instance's configured
repo, GitHub, Kanban, and runtime state; this script only summarizes generated
learning artifacts.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

SCHEMA = "john_lomein_cross_instance_learning_digest/v1"


def utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def today() -> str:
    return time.strftime("%Y-%m-%d", time.localtime())


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def instance_homes(raw: str) -> list[Path]:
    if raw.strip():
        homes = [Path(item.strip()).expanduser() for item in raw.split(",") if item.strip()]
    else:
        homes = sorted((Path.home() / ".john-lomein" / "instances").glob("*/hermes"))
    return [p for p in homes if (p / "instance.yaml").exists()]


def summarize_instance(home: Path) -> dict[str, Any]:
    learning = home / "private" / "learning-steward" / "learning"
    projection = home / "state" / "learning"
    report = read_json(learning / "learning-report.json", {})
    queue = read_json(learning / "candidate-review-queue.json", {})
    workers = []
    for lane in ("maintainer", "forge", "release"):
        workers.append({"lane": lane, **read_json(home / "state" / "workers" / f"{lane}.json", {})})
    slug = report.get("instance") or home.parent.name
    return {
        "slug": slug,
        "display_name": report.get("display_name") or slug,
        "target_repo": report.get("target_repo") or "",
        "generated_at": report.get("generated_at") or "",
        "learning_ok": bool(report.get("ok")) if report else False,
        "status_counts": report.get("status_counts") or {},
        "observation_count": report.get("observation_count") or 0,
        "candidate_count": queue.get("candidate_count", report.get("candidate_count", 0) or 0),
        "candidates": (queue.get("candidates") or [])[:8],
        "journey_card_profiles": sorted((report.get("journey_card_profiles") or {}).keys()),
        "brief_path": report.get("brief_path") or str(projection / "current-operating-brief.md"),
        "queue_path": report.get("candidate_review_queue_path") or str(learning / "candidate-review-queue.md"),
        "workers": workers,
    }


def render_markdown(data: dict[str, Any]) -> str:
    lines = [
        "# John Lomein cross-instance learning digest",
        "",
        f"Generated: `{data['generated_at']}`",
        f"Schema: `{SCHEMA}`",
        "",
        "Boundary: this is a derived digest over learning-steward artifacts. Repo/GitHub/Kanban/runtime state remain canonical.",
        "",
        "## Instances",
        "",
        "| Instance | Repo | Learning | Observations | Candidates | Top statuses |",
        "|---|---|---:|---:|---:|---|",
    ]
    for item in data["instances"]:
        statuses = ", ".join(f"{k}={v}" for k, v in sorted((item.get("status_counts") or {}).items(), key=lambda kv: (-kv[1], kv[0]))[:4]) or "none"
        lines.append(
            f"| {item['display_name']} | `{item.get('target_repo','')}` | {'ok' if item.get('learning_ok') else 'check'} | {item.get('observation_count',0)} | {item.get('candidate_count',0)} | {statuses} |"
        )
    for item in data["instances"]:
        lines.extend(["", f"## {item['display_name']}", ""])
        lines.extend([
            f"- repo: `{item.get('target_repo','')}`",
            f"- learning_report_generated_at: `{item.get('generated_at','')}`",
            f"- brief: `{item.get('brief_path','')}`",
            f"- candidate_queue: `{item.get('queue_path','')}`",
            f"- journey_card_profiles: `{', '.join(item.get('journey_card_profiles') or []) or 'none'}`",
            "- workers:",
        ])
        for worker in item.get("workers") or []:
            lines.append(f"  - `{worker.get('lane')}` status=`{worker.get('status','unknown')}` alive=`{worker.get('alive','')}` updated=`{worker.get('updated_at','')}`")
        candidates = item.get("candidates") or []
        if candidates:
            lines.append("- top candidates:")
            for rec in candidates[:5]:
                lines.append(f"  - `{rec.get('pattern_key','')}` repeated=`{rec.get('repeated_observations',0)}` status=`{rec.get('status','')}`")
        else:
            lines.append("- top candidates: none")
    return "\n".join(lines).rstrip() + "\n"


def build_digest(args: argparse.Namespace) -> dict[str, Any]:
    homes = instance_homes(args.instances)
    instances = [summarize_instance(home) for home in homes]
    return {
        "schema_version": SCHEMA,
        "generated_at": utc(),
        "instance_count": len(instances),
        "instances": instances,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="write a cross-instance john-lomein learning digest")
    p.add_argument("--instances", default="", help="comma-separated runtime HERMES_HOME paths; defaults to ~/.john-lomein/instances/*/hermes")
    p.add_argument("--output-dir", default=str(Path.home() / ".john-lomein" / "reports"), help="directory for markdown/json digest outputs")
    p.add_argument("--json", action="store_true", help="print JSON instead of markdown")
    args = p.parse_args(argv)
    data = build_digest(args)
    out_dir = Path(args.output_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{today()}-cross-instance-learning-digest"
    (out_dir / f"{stem}.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown = render_markdown(data)
    (out_dir / f"{stem}.md").write_text(markdown, encoding="utf-8")
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        print(markdown, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
