from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "john-lomein-exact-head-review.py"
HEAD = "a" * 40


def load_runner():
    spec = importlib.util.spec_from_file_location("john_lomein_exact_head_review", SCRIPT)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def fake_forge(*, pr_head: str = HEAD, worktree_head: str = HEAD, dirty: str = ""):
    def gh_json(cmd, **kwargs):
        return {"number": 125, "state": "OPEN", "headRefOid": pr_head, "headRefName": "forge/issue-125"}

    def run(cmd, **kwargs):
        joined = " ".join(cmd)
        if "rev-parse HEAD" in joined:
            return 0, worktree_head, ""
        if "status --porcelain" in joined:
            return 0, dirty, ""
        raise AssertionError(cmd)

    return SimpleNamespace(gh_json=gh_json, run=run)


def test_binding_requires_exact_open_pr_and_clean_worktree(tmp_path):
    runner = load_runner()
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    result = runner.verify_exact_head_binding(
        env={"BOT_DEFAULT_BRANCH": "main"}, repository="repoowner/sample-project",
        pr_number=125, expected_head=HEAD, worktree=worktree, forge=fake_forge(),
    )
    assert result["head_sha"] == HEAD
    assert result["branch"] == "forge/issue-125"


@pytest.mark.parametrize(
    ("forge", "match"),
    [
        (fake_forge(pr_head="b" * 40), "PR head"),
        (fake_forge(worktree_head="b" * 40), "worktree head"),
        (fake_forge(dirty=" M source.py"), "dirty"),
    ],
)
def test_binding_fails_closed_on_stale_or_dirty_state(tmp_path, forge, match):
    runner = load_runner()
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    with pytest.raises(runner.ExactHeadReviewError, match=match):
        runner.verify_exact_head_binding(
            env={"BOT_DEFAULT_BRANCH": "main"}, repository="repoowner/sample-project",
            pr_number=125, expected_head=HEAD, worktree=worktree, forge=forge,
        )


def test_execute_rejects_pr_head_change_after_reviews(tmp_path):
    runner = load_runner()
    worktree = tmp_path / "worktree"
    home = tmp_path / "home"
    worktree.mkdir()
    calls = {"pr": 0}

    def gh_json(cmd, **kwargs):
        calls["pr"] += 1
        return {"number": 125, "state": "OPEN", "headRefOid": HEAD if calls["pr"] == 1 else "b" * 40, "headRefName": "forge/issue-125"}

    def run(cmd, **kwargs):
        return (0, HEAD, "") if "rev-parse HEAD" in " ".join(cmd) else (0, "", "")

    forge = SimpleNamespace(
        load_env=lambda: {"BOT_HERMES_HOME": str(home), "BOT_REPO": "repoowner/sample-project"},
        gh_json=gh_json,
        run=run,
        run_required_pr_role_reviews=lambda *args, **kwargs: (True, [{"role": "maintainer"}], ""),
    )
    args = SimpleNamespace(repository="repoowner/sample-project", issue=125, pr=125, expected_head=HEAD, worktree=str(worktree))
    with pytest.raises(runner.ExactHeadReviewError, match="PR head"):
        runner.execute(args, forge=forge)


def test_runner_asset_is_deployed_and_maintainer_is_told_to_rerun_it():
    deploy = (ROOT / "scripts" / "deploy-instance.sh").read_text(encoding="utf-8")
    prompt = (ROOT / "scripts" / "john-lomein-maintainer-prompt.txt").read_text(encoding="utf-8")
    assert "john-lomein-exact-head-review.py" in deploy
    assert "john-lomein-exact-head-review.py" in prompt
    assert "--expected-head" in prompt
