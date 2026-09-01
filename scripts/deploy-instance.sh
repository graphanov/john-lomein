#!/usr/bin/env bash
set -euo pipefail
unset HERMES_HONCHO_HOST
if [ $# -ne 1 ]; then
  echo "usage: deploy-instance.sh /path/to/instance" >&2
  exit 2
fi
PRODUCT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTANCE_ARG="$1"
if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required for locked john-lomein product commands: https://docs.astral.sh/uv/" >&2
  exit 2
fi
PRODUCT_PYTHON=(uv run --frozen --project "$PRODUCT_ROOT" python)
SERVICE_REGISTRY="$PRODUCT_ROOT/scripts/john_lomein_service_registry.py"
# Direct deploys join the same lifecycle transaction as setup. Setup already
# passes the locked descriptor through make, so its staged manifest stays bound.
if [ -z "${JOHN_LOMEIN_SERVICE_LOCK_FD:-}" ]; then
  exec "${PRODUCT_PYTHON[@]}" "$SERVICE_REGISTRY" \
    run-locked -- bash "$0" "$INSTANCE_ARG"
fi
"${PRODUCT_PYTHON[@]}" "$SERVICE_REGISTRY" assert-locked
DEPLOY_OWNS_MANIFEST_SNAPSHOT=0
cleanup_deploy_manifest() {
  local original_status=$?
  local cleanup_status=0
  trap - EXIT
  set +e
  if [ "$DEPLOY_OWNS_MANIFEST_SNAPSHOT" = "1" ] && \
    [ -n "${JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT:-}" ] && \
    { [ -e "$JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT" ] || \
      [ -L "$JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT" ]; }
  then
    rm -f -- "$JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT"
    cleanup_status=$?
  fi
  if [ "$cleanup_status" -ne 0 ]; then
    echo "deploy manifest cleanup failed; inspect the owner-private staged file" >&2
    if [ "$original_status" -eq 0 ]; then
      original_status=70
    fi
  fi
  exit "$original_status"
}
if [ -z "${JOHN_LOMEIN_SETUP_MANIFEST_SOURCE:-}" ] && \
  [ -z "${JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT:-}" ] && \
  [ -z "${JOHN_LOMEIN_SETUP_MANIFEST_SHA256:-}" ]
then
  trap cleanup_deploy_manifest EXIT
  if DEPLOY_MANIFEST_BINDING="$(
    "${PRODUCT_PYTHON[@]}" \
      "$PRODUCT_ROOT/scripts/john-lomein-stage-manifest.py" \
      stage "$INSTANCE_ARG"
  )"
  then
    eval "$DEPLOY_MANIFEST_BINDING"
    unset DEPLOY_MANIFEST_BINDING
    DEPLOY_OWNS_MANIFEST_SNAPSHOT=1
    export JOHN_LOMEIN_SETUP_MANIFEST_SOURCE
    export JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT
    export JOHN_LOMEIN_SETUP_MANIFEST_SHA256
  else
    DEPLOY_MANIFEST_STATUS=$?
    echo "deploy preflight failed: instance manifest could not be staged safely" >&2
    exit "$DEPLOY_MANIFEST_STATUS"
  fi
elif [ -z "${JOHN_LOMEIN_SETUP_MANIFEST_SOURCE:-}" ] || \
  [ -z "${JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT:-}" ] || \
  [ -z "${JOHN_LOMEIN_SETUP_MANIFEST_SHA256:-}" ]
then
  echo "deploy preflight failed: setup manifest binding is incomplete" >&2
  exit 2
fi
verify_deploy_manifest() {
  "${PRODUCT_PYTHON[@]}" \
    "$PRODUCT_ROOT/scripts/read-instance-env.py" "$INSTANCE_ARG" >/dev/null
  "${PRODUCT_PYTHON[@]}" \
    "$PRODUCT_ROOT/scripts/john-lomein-stage-manifest.py" verify \
    "$JOHN_LOMEIN_SETUP_MANIFEST_SOURCE" \
    "$JOHN_LOMEIN_SETUP_MANIFEST_SHA256"
}
eval "$("${PRODUCT_PYTHON[@]}" "$PRODUCT_ROOT/scripts/read-instance-env.py" "$INSTANCE_ARG")"
verify_deploy_manifest
export HERMES_REAL_HOME="${HERMES_REAL_HOME:-$HOME}"
export JOHN_LOMEIN_AUTH_AUTHORITY_HOME="${JOHN_LOMEIN_AUTH_AUTHORITY_HOME:-$HERMES_REAL_HOME/.hermes}"
export JL_INSTANCE_DIR JL_INSTANCE_MANIFEST JL_INSTANCE_MANIFEST_INPUT
export BOT_SLUG BOT_DISPLAY_NAME BOT_REPO BOT_DEFAULT_BRANCH BOT_LOCAL BOT_HERMES_HOME
export BOT_MISSION_COMPLETE BOT_REQUESTED_ACTIVATION BOT_ACTIVATION
export BOT_MUTATION_REQUESTED BOT_MUTATION_ENABLED BOT_DISCORD_REQUESTED BOT_DISCORD_ENABLED
export BOT_GUIDE_GATEWAY_REQUESTED BOT_GUIDE_GATEWAY_ENABLED
export BOT_PROTECTED_RELEASE_BROKER_REQUESTED BOT_PROTECTED_RELEASE_BROKER_ENABLED
export BOT_OSC_PORTFOLIO_REQUESTED BOT_OSC_PORTFOLIO_ENABLED
export BOT_KEEP_AWAKE_ON_AC BOT_MAINTAINER_PROFILE BOT_FORGE_PROFILE BOT_GUIDE_PROFILE
export BOT_OVERWATCH_PROFILE BOT_LEARNING_STEWARD_PROFILE BOT_NPM_TAG BOT_PUBLISH_WORKFLOW
export BOT_MODEL_PROVIDER BOT_FALLBACK_PROVIDER HERMES_REAL_HOME JOHN_LOMEIN_AUTH_AUTHORITY_HOME
export BOT_MODEL_MEMORY_ISOLATION BOT_STEWARD_PRIVATE_ROOT BOT_STEWARD_PROJECTION_ROOT
export HERMES_HOME="$BOT_HERMES_HOME"
export JOHN_LOMEIN_INSTANCE_HERMES_HOME="$BOT_HERMES_HOME"
export JOHN_LOMEIN_HERMES_HOME="$BOT_HERMES_HOME"
export MNEMOSYNE_DATA_DIR="$BOT_STEWARD_PRIVATE_ROOT/mnemosyne/data"
export BOT_HERMES_MANAGED_ROOT="$BOT_HERMES_HOME/managed-policy"

"${PRODUCT_PYTHON[@]}" - "$PRODUCT_ROOT" "$JL_INSTANCE_MANIFEST_INPUT" "$BOT_HERMES_HOME" <<'PY'
from pathlib import Path
import os, stat, sys, tempfile
import yaml

product=Path(sys.argv[1])
sys.path.insert(0, str(product/'scripts'))
from john_lomein_manifest_contract import (
    validate_deploy_managed_paths,
    validate_manifest_contract,
)
from john_lomein_profile_contract import canonical_role_profiles
from john_lomein_honcho_contract import honcho_settings

try:
    manifest=yaml.safe_load(Path(sys.argv[2]).read_text(encoding='utf-8')) or {}
    validate_manifest_contract(manifest)
    slug=str((manifest.get('instance') or {}).get('slug') or '').strip()
    settings=honcho_settings(manifest,instance_slug=slug)
    validate_deploy_managed_paths(
        Path(sys.argv[3]),
        canonical_role_profiles(manifest),
    )
    managed_root=Path(sys.argv[3])/'managed-policy'
    bootstrap=managed_root/'bootstrap'
    for directory in (managed_root,bootstrap):
        if directory.is_symlink():
            raise ValueError(f'managed policy path is symlink: {directory}')
        if directory.exists():
            info=directory.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o022
            ):
                raise ValueError(f'unsafe managed policy directory: {directory}')
    bootstrap_config=bootstrap/'config.yaml'
    if bootstrap_config.exists() or bootstrap_config.is_symlink():
        info=bootstrap_config.lstat()
        if (
            bootstrap_config.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_mode & 0o022
        ):
            raise ValueError(
                f'unsafe bootstrap managed policy config: {bootstrap_config}'
            )
except (RuntimeError, ValueError) as exc:
    raise SystemExit(str(exc)) from exc
PY

if ! command -v hermes >/dev/null 2>&1; then
  echo "hermes is required for the continuity hook capability canary" >&2
  exit 2
fi
"${PRODUCT_PYTHON[@]}" \
  "$PRODUCT_ROOT/scripts/john-lomein-continuity-hook-canary.py" \
  --hermes "$(command -v hermes)" \
  --timeout 45 >/dev/null

"${PRODUCT_PYTHON[@]}" \
  "$PRODUCT_ROOT/scripts/john_lomein_memory_boundary_migration.py" \
  --runtime-home "$BOT_HERMES_HOME" \
  --private-root "$BOT_STEWARD_PRIVATE_ROOT" \
  --projection-root "$BOT_STEWARD_PROJECTION_ROOT" \
  --quiet

mkdir -p "$BOT_HERMES_HOME" "$BOT_HERMES_HOME/scripts" "$BOT_HERMES_HOME/state" "$BOT_HERMES_HOME/state/honcho" "$BOT_HERMES_HOME/private/honcho-deletion-tombstones" "$BOT_HERMES_HOME/private/owner-overrides" "$BOT_HERMES_HOME/private/owner-overrides/inbox" "$BOT_HERMES_HOME/private/review-receipts" "$BOT_HERMES_HOME/state/review-runs" "$BOT_HERMES_HOME/state/autonomy" "$BOT_HERMES_HOME/state/continuity" "$BOT_HERMES_HOME/state/workers" "$BOT_HERMES_HOME/state/learning" "$BOT_HERMES_HOME/private/release-bundles" "$BOT_HERMES_HOME/state/protected-actions" "$BOT_HERMES_HOME/state/protected-actions/outbox" "$BOT_HERMES_HOME/state/protected-actions/receipts" "$BOT_HERMES_HOME/state/protected-releases" "$BOT_HERMES_HOME/state/protected-releases/outbox" "$BOT_HERMES_HOME/state/protected-releases/receipts" "$BOT_HERMES_HOME/logs" "$BOT_HERMES_HOME/logs/workers" "$BOT_HERMES_HOME/work" "$BOT_HERMES_HOME/plugins" "$BOT_HERMES_HOME/private" "$BOT_STEWARD_PRIVATE_ROOT" "$BOT_STEWARD_PRIVATE_ROOT/learning" "$MNEMOSYNE_DATA_DIR" "$BOT_HERMES_MANAGED_ROOT/bootstrap"
chmod 700 "$BOT_HERMES_HOME" "$BOT_HERMES_HOME/scripts" "$BOT_HERMES_HOME/state" "$BOT_HERMES_HOME/state/honcho" "$BOT_HERMES_HOME/private/honcho-deletion-tombstones" "$BOT_HERMES_HOME/private/owner-overrides" "$BOT_HERMES_HOME/private/owner-overrides/inbox" "$BOT_HERMES_HOME/private/review-receipts" "$BOT_HERMES_HOME/state/review-runs" "$BOT_HERMES_HOME/state/autonomy" "$BOT_HERMES_HOME/state/continuity" "$BOT_HERMES_HOME/state/workers" "$BOT_HERMES_HOME/state/learning" "$BOT_HERMES_HOME/private/release-bundles" "$BOT_HERMES_HOME/state/protected-actions" "$BOT_HERMES_HOME/state/protected-actions/outbox" "$BOT_HERMES_HOME/state/protected-actions/receipts" "$BOT_HERMES_HOME/state/protected-releases" "$BOT_HERMES_HOME/state/protected-releases/outbox" "$BOT_HERMES_HOME/state/protected-releases/receipts" "$BOT_HERMES_HOME/logs" "$BOT_HERMES_HOME/logs/workers" "$BOT_HERMES_HOME/work" "$BOT_HERMES_HOME/plugins" "$BOT_HERMES_HOME/private" "$BOT_STEWARD_PRIVATE_ROOT" "$BOT_STEWARD_PRIVATE_ROOT/learning" "$BOT_STEWARD_PRIVATE_ROOT/mnemosyne" "$MNEMOSYNE_DATA_DIR" "$BOT_HERMES_MANAGED_ROOT" "$BOT_HERMES_MANAGED_ROOT/bootstrap"
chmod 700 \
  "$BOT_HERMES_HOME/private" \
  "$BOT_STEWARD_PRIVATE_ROOT" \
  "$BOT_STEWARD_PRIVATE_ROOT/learning" \
  "$BOT_STEWARD_PRIVATE_ROOT/mnemosyne" \
  "$MNEMOSYNE_DATA_DIR"
bootstrap_tmp="$(mktemp "$BOT_HERMES_MANAGED_ROOT/bootstrap/.config.yaml.XXXXXX")"
printf '{}\n' > "$bootstrap_tmp"
chmod 600 "$bootstrap_tmp"
mv -f "$bootstrap_tmp" "$BOT_HERMES_MANAGED_ROOT/bootstrap/config.yaml"
# Suppress any unrelated host-wide /etc/hermes overlay during bootstrap. Every
# model-facing profile invocation below switches to its exact role policy.
export HERMES_MANAGED_DIR="$BOT_HERMES_MANAGED_ROOT/bootstrap"
if ! "${PRODUCT_PYTHON[@]}" - "$JL_INSTANCE_MANIFEST_INPUT" "$BOT_HERMES_HOME/instance.yaml" <<'PY'
import os, sys
try:
    same = os.path.exists(sys.argv[2]) and os.path.samefile(sys.argv[1], sys.argv[2])
except Exception:
    same = False
raise SystemExit(0 if same else 1)
PY
then
  manifest_tmp="$(mktemp "$BOT_HERMES_HOME/.instance.yaml.XXXXXX")"
  cp "$JL_INSTANCE_MANIFEST_INPUT" "$manifest_tmp"
  chmod 600 "$manifest_tmp"
  mv -f "$manifest_tmp" "$BOT_HERMES_HOME/instance.yaml"
fi
chmod 600 "$BOT_HERMES_HOME/instance.yaml"

"${PRODUCT_PYTHON[@]}" - "$BOT_HERMES_HOME/plugins/mnemosyne" "$HOME/mnemosyne/hermes_memory_provider" "$HOME/.hermes/plugins/mnemosyne" <<'PY'
from pathlib import Path
import sys

destination = Path(sys.argv[1])
candidates = [Path(raw).expanduser() for raw in sys.argv[2:]]
source = next((path.resolve() for path in candidates if path.exists()), None)
if destination.exists() or destination.is_symlink():
    if not destination.is_symlink():
        raise SystemExit(
            f"unsafe Mnemosyne runtime dependency path is not a symlink: {destination}"
        )
    destination.unlink()
if source is not None:
    destination.symlink_to(source, target_is_directory=source.is_dir())
PY

# OAuth material is never copied into a model-visible provider path. After
# profiles and sealed scripts exist, deployment removes historical Codex
# projections; the launch-time controller broker owns provider credentials.

render_and_configure() {
  "${PRODUCT_PYTHON[@]}" - "$PRODUCT_ROOT" "$JL_INSTANCE_MANIFEST_INPUT" "$BOT_HERMES_HOME" <<'PY'
from __future__ import annotations
import hashlib, json, os, re, shutil, stat, subprocess, sys, tempfile
from pathlib import Path
import yaml
product=Path(sys.argv[1]); manifest=Path(sys.argv[2]); H=Path(sys.argv[3])
sys.path.insert(0, str(product/'scripts'))
from john_lomein_factory_receipts import (
    prompt_data,
    safe_authority_level,
    safe_npm_tag,
    safe_publish_workflow,
)
from john_lomein_manifest_contract import (
    confined_omh_copy_paths,
    effective_authority_posture,
    validate_manifest_contract,
    validate_omh_source_tree,
)
from john_lomein_memory_contract import (
    agent_memory_managed_policy,
    apply_agent_memory_boundary,
    managed_policy_directory,
)
from john_lomein_collaboration_contract import collaboration_policy
from john_lomein_honcho_contract import honcho_settings, write_profile_honcho_config
from john_lomein_continuity import initialize_store
from john_lomein_persona_contract import load_persona_core
from john_lomein_profile_contract import canonical_role_profiles
bot=yaml.safe_load(manifest.read_text(encoding='utf-8')) or {}
contract=validate_manifest_contract(bot)
flags=contract['flags']
posture=effective_authority_posture(bot, contract=contract)
autonomy_policy=contract['autonomy']
collaboration=contract['collaboration']
owner_override=contract['owner_override']
owner_github_logins=contract['owner_github_logins']
review_quorum=contract['review_quorum']
prompt_fields=contract['prompt']
inst=bot.get('instance') or {}; mission=bot.get('mission') or {}; target=bot.get('target') or {}; runtime=bot.get('runtime') or {}; profiles=bot.get('profiles') or {}; model=bot.get('model') or {}; fallback=model.get('fallback') or {}; authority=bot.get('authority') or {}; gates=bot.get('gates') or {}; discord=bot.get('discord') or {}; secrets=bot.get('secrets') or {}; workflows=bot.get('workflows') or {}; learning=bot.get('learning') or {}; forge=bot.get('forge') or {}; cron=bot.get('cron') or {}; portfolio=bot.get('open_scaffold_portfolio') or bot.get('osc_portfolio') or {}; release=bot.get('release') or {}
slug=os.environ['BOT_SLUG']; display=os.environ['BOT_DISPLAY_NAME']
honcho_runtime=honcho_settings(bot, instance_slug=slug)
repo=os.environ['BOT_REPO']; branch=os.environ['BOT_DEFAULT_BRANCH']; local=os.environ['BOT_LOCAL']; home=str(H)
npm_tag=safe_npm_tag(os.environ.get('BOT_NPM_TAG') or release.get('npm_tag'))
publish_workflow=safe_publish_workflow(os.environ.get('BOT_PUBLISH_WORKFLOW') or release.get('publish_workflow'))
persona_path=product/'persona'/'JOHN_LOMEIN.md'
persona_core,persona_version,persona_sha256=load_persona_core(persona_path)
role_profiles=canonical_role_profiles(bot)
role_skills={
 'maintainer':['john-lomein-maintainer','john-lomein-communication','john-lomein-native-workflows'],
 'forge':['john-lomein-forge','john-lomein-communication','john-lomein-native-workflows'],
 'guide':['john-lomein-guide-playground','john-lomein-guide-proposals','john-lomein-build-room','john-lomein-communication','john-lomein-native-workflows'],
 'overwatch':['john-lomein-overwatch','john-lomein-communication','john-lomein-native-workflows'],
 'learning_steward':['john-lomein-learning-steward','john-lomein-communication','john-lomein-native-workflows'],
}
default_omh_skills={
 'maintainer':['oh-my-hermes','code-review','ultrawork','ultraqa','deploy-and-monitor','agent-ops-review'],
 'forge':['oh-my-hermes','ralplan','deep-interview','ultrawork','code-review','ultraqa'],
 'guide':['oh-my-hermes','deep-interview','ralplan','source-finder'],
 'overwatch':['oh-my-hermes','agent-ops-review','code-review','ultraqa','doctor'],
 'learning_steward':['oh-my-hermes','workflow-learning','memory-sync','agent-ops-review','doctor'],
}
omh_enabled=flags['omh_enabled']
omh_required=flags['omh_required']
omh_home_input=Path(os.path.expanduser(str(workflows.get('omh_home') or (H/'omh'))))
if not omh_home_input.is_absolute():
    raise SystemExit('workflows.omh_home must be an absolute instance-local path')
omh_home=omh_home_input.resolve()
try:
    omh_relative=omh_home.relative_to(H)
except ValueError as exc:
    raise SystemExit('workflows.omh_home must stay inside runtime.hermes_home') from exc
if len(omh_relative.parts)!=1 or not omh_relative.name.startswith('omh'):
    raise SystemExit('workflows.omh_home must be a dedicated top-level OMH subtree')
# John instances consume the skill set installed into their own OMH home.
# A personal ~/.omh is neither a deployment prerequisite nor an authority
# source for an appliance.
omh_skill_source=(omh_home/'skills').resolve()
def is_omh_external_dir(value):
    raw=Path(os.path.expanduser(str(value)))
    candidate=(raw if raw.is_absolute() else H/raw).resolve()
    return candidate == omh_home or omh_home in candidate.parents

implementation_mode=str(workflows.get('implementation_mode') or 'hermes_direct')
if implementation_mode not in {'hermes_direct','omh_codex'}:
    raise SystemExit('unsupported workflows.implementation_mode')
if implementation_mode=='omh_codex' and not omh_enabled:
    raise SystemExit('omh_codex requires workflows.omh_enabled: true')
implementation_executor=str(workflows.get('implementation_executor') or 'codex')
hermes_direct_fallback=str(workflows.get('hermes_direct_fallback') or 'blocked_only')
codex_home=Path(os.path.expanduser(str(workflows.get('codex_home') or os.environ.get('CODEX_HOME') or (Path.home()/'.codex')))).resolve()
codex_model=str(workflows.get('codex_model') or model.get('default') or model.get('model') or 'gpt-5.5')
codex_reasoning_effort=str(workflows.get('codex_reasoning_effort') or model.get('reasoning_effort') or 'xhigh')
codex_timeout_seconds=int(workflows.get('codex_timeout_seconds') or 3600)
configured_omh=contract['omh_skills_by_role']
def resolve_hermes_python():
    explicit=os.environ.get('HERMES_PYTHON')
    if explicit and Path(explicit).expanduser().exists():
        return str(Path(explicit).expanduser())
    hermes_bin=shutil.which('hermes')
    if hermes_bin:
        hermes_dir=Path(hermes_bin).expanduser().parent
        for name in ('python3','python'):
            candidate=hermes_dir/name
            if candidate.is_file() and os.access(candidate,os.X_OK):
                return str(candidate)
        try:
            first=Path(hermes_bin).read_text(encoding='utf-8', errors='ignore').splitlines()[0]
            if first.startswith('#!'):
                candidate=Path(first[2:].strip()).expanduser()
                if candidate.name.startswith('python') and candidate.is_file() and os.access(candidate,os.X_OK):
                    return str(candidate)
        except Exception:
            pass
    fallback=Path.home()/'.hermes/hermes-agent/venv/bin/python'
    if fallback.exists():
        return str(fallback)
    return sys.executable
hermes_python=resolve_hermes_python()
hermes_venv=str(Path(hermes_python).expanduser().parent.parent)
def atomic_text(path, text, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.deploy-', dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
def normalize_skill_frontmatter_text(text):
    if not text.startswith('---'):
        return text
    end=text.find('\n---', 3)
    if end < 0:
        return text
    front=text[3:end]
    body=text[end+len('\n---'):]
    lines=[]
    changed=False
    for line in front.splitlines():
        m=re.match(r'^(description:\s*)(.+?)\s*$', line)
        if m:
            value=m.group(2).strip()
            if value and not value.startswith(('"', "'", '|', '>')):
                line=m.group(1)+json.dumps(value)
                changed=True
        lines.append(line)
    if not changed:
        return text
    candidate='---\n'+'\n'.join(lines).rstrip()+'\n---'+body
    try:
        yaml.safe_load('\n'.join(lines))
        return candidate
    except Exception:
        return text
def write_normalized_skill(src, dst):
    atomic_text(dst, normalize_skill_frontmatter_text(src.read_text(encoding='utf-8')), 0o600)
def role_omh_skills(role):
    if not omh_enabled:
        return []
    raw=configured_omh.get(role)
    if isinstance(raw, list):
        return [str(x) for x in raw]
    return default_omh_skills.get(role, [])
omh_report={}
forbidden=prompt_fields['gates']['forbidden_paths']
labels=prompt_fields['gates']['readiness_labels']
autonomous_safe_labels=prompt_fields['gates']['autonomous_safe_labels']
triage_needed_label=str(gates.get('triage_needed_label') or 'triage-needed')
portfolio_enabled=posture['portfolio_enabled']
portfolio_labels=portfolio.get('issue_labels') or ['portfolio-gap','ready-for-implementation']
portfolio_cadence=str(cron.get('osc_portfolio_cadence') or portfolio.get('cadence') or 'every 6h')
portfolio_max_gaps=int(portfolio.get('max_gaps_per_tick') or 3)
portfolio_branch_prefix=str(portfolio.get('branch_prefix') or 'portfolio/')
def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
mission_fields=prompt_fields['mission']
mission_statement=mission_fields['statement']
mission_roadmap_sources=mission_fields['roadmap_sources']
mission_owner_signal_policy=mission_fields['owner_signal_policy']
mission_personality_voice=mission_fields['voice']
mission_personality_creative_posture=mission_fields['creative_posture']
owner_approvers=[str(x) for x in as_list(authority.get('owner_approvers') or discord.get('owner_user_ids'))]
trust_public_key_sha256=str(authority.get('trust_public_key_sha256') or discord.get('trust_public_key_sha256') or '')
discord_owner_user_ids=[str(x) for x in as_list(discord.get('owner_user_ids'))]
discord_collaborator_user_ids=[str(x) for x in as_list(discord.get('trusted_collaborator_user_ids'))]
discord_untrusted_example_channels=[str(x) for x in as_list(discord.get('untrusted_example_channels'))]
def md_list(items): return '\n'.join(f'- {prompt_data(x)}' for x in items) if items else '- none configured'
ctx={
 'INSTANCE_SLUG': prompt_data(slug),
 'INSTANCE_DISPLAY_NAME': prompt_data(display),
 'TARGET_REPO': prompt_data(repo),
 'TARGET_DEFAULT_BRANCH': prompt_data(branch),
 'RUNTIME_ACTIVATION': prompt_data(os.environ['BOT_ACTIVATION']),
 'RUNTIME_MUTATION_ENABLED': prompt_data(posture['mutation_enabled']),
 'DISCORD_ENABLED': prompt_data(posture['discord_enabled']),
 'DISCORD_GUIDE_GATEWAY_ENABLED': prompt_data(posture['guide_gateway_enabled']),
 'AUTHORITY_MAINTAINER_LEVEL': prompt_data(safe_authority_level(authority.get('maintainer_level'),'authority.maintainer_level','2')),
 'AUTHORITY_FORGE_LEVEL': prompt_data(safe_authority_level(authority.get('forge_level'),'authority.forge_level','1')),
 'AUTHORITY_GUIDE_LEVEL': prompt_data(safe_authority_level(authority.get('guide_level'),'authority.guide_level','1')),
 'AUTHORITY_OVERWATCH_LEVEL': prompt_data(safe_authority_level(authority.get('overwatch_level'),'authority.overwatch_level','1.5')),
 'GATES_FORBIDDEN_PATHS_MD': md_list(forbidden),
 'GATES_READINESS_LABELS_MD': md_list(labels),
 'MISSION_OWNER_AUTHORED': prompt_data(posture['mission_complete']),
 'MISSION_STATEMENT': prompt_data(mission_statement),
 'MISSION_ROADMAP_SOURCES_MD': md_list(mission_roadmap_sources),
 'MISSION_OWNER_SIGNAL_POLICY': prompt_data(mission_owner_signal_policy),
 'MISSION_PERSONALITY_VOICE': prompt_data(mission_personality_voice),
 'MISSION_PERSONALITY_CREATIVE_POSTURE': prompt_data(mission_personality_creative_posture),
 'JOHN_LOMEIN_PERSONA_CORE': persona_core,
}
def render(text):
    for k,v in ctx.items():
        text=text.replace('{{'+k+'}}', str(v))
    unresolved=sorted(set(re.findall(r'\{\{[A-Z0-9_]+\}\}', text)))
    if unresolved:
        raise SystemExit(f'unresolved profile placeholders: {unresolved}')
    return text
# env import, no values printed
ENV_KEY_RE=re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
def normalize_env_key(raw_key):
    key=str(raw_key or '').strip()
    if key.startswith('export '):
        key=key[len('export '):].strip()
    return key if ENV_KEY_RE.match(key) else ''
allowed_import_keys={normalize_env_key(k) for k in (secrets.get('env_keys') or [])}
allowed_import_keys={k for k in allowed_import_keys if k}
KNOWN_CREDENTIAL_KEYS={'GH_TOKEN','GITHUB_TOKEN','DISCORD_BOT_TOKEN','BOT_DISCORD_TOKEN'}
CREDENTIAL_KEY_RE=re.compile(r'^[A-Z][A-Z0-9_]*(?:_API_KEY|_ACCESS_TOKEN|_SECRET_KEY)$')
UNSAFE_ENV_PREFIXES=('BOT_','HERMES_','JOHN_LOMEIN_','JL_','DYLD_','LD_')
UNSAFE_ENV_NAMES={'PATH','PYTHONPATH','BASH_ENV','ENV','SHELLOPTS','SSL_CERT_FILE','REQUESTS_CA_BUNDLE','GH_CONFIG_DIR','GIT_CONFIG_GLOBAL','GIT_CONFIG_SYSTEM'}
unsafe_keys=sorted(k for k in allowed_import_keys if k not in KNOWN_CREDENTIAL_KEYS and (k.startswith(UNSAFE_ENV_PREFIXES) or k in UNSAFE_ENV_NAMES or CREDENTIAL_KEY_RE.fullmatch(k) is None))
if unsafe_keys:
    raise SystemExit(f'secrets.env_keys contains non-credential or process-control names: {unsafe_keys}')
imported={}
for env_file in secrets.get('import_env_files') or []:
    p=Path(os.path.expanduser(str(env_file)))
    if not p.exists():
        continue
    for raw in p.read_text(encoding='utf-8', errors='ignore').splitlines():
        line=raw.strip()
        if not line or line.startswith('#') or '=' not in line: continue
        k,v=line.split('=',1)
        k=normalize_env_key(k); v=v.strip().strip('"').strip("'")
        if k and k in allowed_import_keys:
            imported[k]=v
if not imported:
    # GH auth repair can use gh's own token; no failure here.
    pass
# runtime env files: keep public Discord tokens out of the runtime root so
# scheduler-only gateways do not accidentally connect with the guide token.
def is_discord_secret_key(k): return k.startswith('DISCORD_') or k == 'BOT_DISCORD_TOKEN'
def is_github_secret_key(k): return k in {'GH_TOKEN','GITHUB_TOKEN'}
def is_runtime_control_key(k):
    # Imported env files are for credentials (for example GH_TOKEN), not for
    # authority/routing/runtime control. Deny whole control prefixes so a future
    # BOT_*/JOHN_LOMEIN_*/JL_*/HERMES_* knob cannot override generated instance
    # truth by being appended after manifest-derived values.
    return (
        k.startswith('BOT_')
        or k.startswith('JOHN_LOMEIN_')
        or k.startswith('JL_')
        or k == 'HERMES_HOME'
        or k.startswith('HERMES_')
    )
runtime_imported={
    k:v for k,v in imported.items()
    if not is_discord_secret_key(k)
    and not is_github_secret_key(k)
    and not is_runtime_control_key(k)
}
runtime_env=H/'.env'
lines=[]
for k,v in sorted(runtime_imported.items()):
    lines.append(f'{k}={v}')
atomic_text(runtime_env, '\n'.join(lines).rstrip()+'\n', 0o600)
# env sourced by no-agent scripts
script_env=H/'scripts'/'john-lomein-instance.env'
def sq(s): return "'" + str(s).replace("'", "'\\''") + "'"
script_lines=[
 f'BOT_NAME={sq("john-lomein")}', f'BOT_SLUG={sq(slug)}', f'BOT_DISPLAY_NAME={sq(display)}', f'BOT_REPO={sq(repo)}', f'BOT_DEFAULT_BRANCH={sq(branch)}', f'BOT_LOCAL={sq(local)}', f'BOT_HERMES_HOME={sq(home)}', f'BOT_HERMES_MANAGED_ROOT={sq(str(H/"managed-policy"))}', f'BOT_PRODUCT_ROOT={sq(str(product))}', f'HERMES_HOME={sq(home)}', f'HERMES_REAL_HOME={sq(os.environ["HERMES_REAL_HOME"])}', f'JOHN_LOMEIN_AUTH_AUTHORITY_HOME={sq(os.environ["JOHN_LOMEIN_AUTH_AUTHORITY_HOME"])}', f'BOT_MISSION_COMPLETE={sq("1" if posture["mission_complete"] else "0")}', f'BOT_REQUESTED_ACTIVATION={sq(posture["requested_activation"])}', f'BOT_ACTIVATION={sq(posture["activation"])}', f'BOT_MUTATION_REQUESTED={sq("1" if posture["requested_mutation_enabled"] else "0")}', f'BOT_MUTATION_ENABLED={sq("1" if posture["mutation_enabled"] else "0")}', f'BOT_DISCORD_REQUESTED={sq("1" if posture["requested_discord_enabled"] else "0")}', f'BOT_DISCORD_ENABLED={sq("1" if posture["discord_enabled"] else "0")}', f'BOT_GUIDE_GATEWAY_REQUESTED={sq("1" if posture["requested_guide_gateway_enabled"] else "0")}', f'BOT_GUIDE_GATEWAY_ENABLED={sq("1" if posture["guide_gateway_enabled"] else "0")}', f'BOT_PROTECTED_RELEASE_BROKER_REQUESTED={sq("1" if posture["requested_protected_release_broker_enabled"] else "0")}', f'BOT_PROTECTED_RELEASE_BROKER_ENABLED={sq("1" if posture["protected_release_broker_enabled"] else "0")}', f'BOT_KEEP_AWAKE_ON_AC={sq("1" if flags["runtime_keep_awake_on_ac"] else "0")}', f'BOT_OWNER_APPROVERS={sq(",".join(owner_approvers))}', f'BOT_TRUST_PUBLIC_KEY_SHA256={sq(trust_public_key_sha256)}', f'BOT_DISCORD_OWNER_USER_IDS={sq(",".join(discord_owner_user_ids))}', f'BOT_DISCORD_TRUSTED_COLLABORATOR_USER_IDS={sq(",".join(discord_collaborator_user_ids))}', f'BOT_DISCORD_UNTRUSTED_EXAMPLE_CHANNELS={sq(",".join(discord_untrusted_example_channels))}', f'BOT_TEST_CMD={sq(gates.get("test_cmd") or "")}', f'BOT_FORBIDDEN_PATHS_JSON={sq(json.dumps(forbidden, separators=(",",":")))}', f'BOT_READINESS_LABELS={sq(",".join(labels))}', f'BOT_AUTONOMOUS_SAFE_LABELS={sq(",".join(autonomous_safe_labels))}', f'BOT_TRIAGE_NEEDED_LABEL={sq(triage_needed_label)}', f'BOT_MAX_OPEN_TOTAL_PRS={sq((bot.get("parallel_lanes") or {}).get("max_open_total_prs") or 4)}', f'BOT_MAX_OPEN_BOT_PRS={sq((bot.get("parallel_lanes") or {}).get("max_open_bot_prs") or 3)}', f'BOT_MAX_OPEN_FORGE_PRS={sq((bot.get("parallel_lanes") or {}).get("max_open_forge_prs") or 2)}', f'BOT_FORGE_IN_CYCLE_REVISE_MAX_ROUNDS={sq(forge.get("in_cycle_revise_max_rounds") or 2)}', f'BOT_FORGE_REVISE_RETRY_AFTER_SECONDS={sq(forge.get("revise_retry_after_seconds") or 1800)}', f'BOT_FORGE_REVISE_MAX_RETRIES={sq(forge.get("revise_max_retries") or 3)}', f'BOT_ALLOWED_CHANNELS={sq(",".join(str(x) for x in (discord.get("allowed_channels") or [])))}', f'BOT_FREE_RESPONSE_CHANNELS={sq(",".join(str(x) for x in (discord.get("free_response_channels") or [])))}', f'BOT_NO_THREAD_CHANNELS={sq(",".join(str(x) for x in (discord.get("no_thread_channels") or [])))}', f'BOT_BUILD_CHANNEL={sq(discord.get("build_channel") or "")}', f'BOT_PLAYGROUND_CHANNEL={sq(discord.get("playground_channel") or "")}', f'BOT_FORGE_CHANNEL={sq(discord.get("forge_channel") or "")}', f'BOT_NOTIFICATIONS_CHANNEL={sq(discord.get("bot_notifications_channel") or discord.get("build_channel") or "")}', f'BOT_ANNOUNCEMENTS_CHANNEL={sq(discord.get("announcements_channel") or "")}', f'BOT_DELIVER={sq(cron.get("deliver") or discord.get("deliver") or "local")}', f'BOT_MAINTAINER_CADENCE={sq(cron.get("maintainer_cadence") or "every 2m")}', f'BOT_FORGE_CADENCE={sq(cron.get("forge_cadence") or "every 15m")}', f'BOT_OVERWATCH_CADENCE={sq(cron.get("overwatch_cadence") or "every 5m")}', f'BOT_WATCHDOG_CADENCE={sq(cron.get("watchdog_cadence") or "every 7m")}',
 f'BOT_MODEL_PROVIDER={sq(model.get("provider") or "openai-codex")}', f'BOT_FALLBACK_PROVIDER={sq(fallback.get("provider") or "")}',
 f'BOT_MODEL_MEMORY_ISOLATION={sq(contract["model_memory_isolation"])}', f'BOT_STEWARD_PRIVATE_ROOT={sq(str(H/"private"/"learning-steward"))}', f'BOT_STEWARD_PROJECTION_ROOT={sq(str(H/"state"/"learning"))}',
 f'BOT_OWNER_GITHUB_LOGINS={sq(",".join(owner_github_logins))}', f'BOT_OWNER_OVERRIDE_ENABLED={sq("1" if owner_override["enabled"] else "0")}', f'BOT_OWNER_OVERRIDE_KEY_ID={sq(owner_override["key_id"])}', f'BOT_OWNER_OVERRIDE_PUBLIC_KEY_SHA256={sq(owner_override["public_key_sha256"])}', f'BOT_OWNER_OVERRIDE_DISCORD_USER_IDS={sq(",".join(owner_override["allowed_discord_user_ids"]))}',
 f'BOT_REVIEW_QUORUM_POLICY_JSON={sq(json.dumps(review_quorum, sort_keys=True, separators=(",",":")))}',
 f'BOT_REVIEW_ONLY_PROFILES_QUALIFIED={sq("1" if contract["flags"]["review_only_profiles_qualified"] else "0")}',
 f'BOT_HONCHO_BASE_URL={sq(honcho_runtime["base_url"])}', f'BOT_HONCHO_REDIS_URL={sq(honcho_runtime["redis_url"])}', f'BOT_HONCHO_WORKSPACE={sq(honcho_runtime["workspace"])}', f'BOT_HONCHO_DATABASE={sq(honcho_runtime["database"])}', f'BOT_HONCHO_WATCHDOG_ENABLED={sq("1" if honcho_runtime["watchdog_enabled"] else "0")}', f'BOT_HONCHO_SERVER_ROOT={sq(honcho_runtime["server_root"])}', f'BOT_HONCHO_CHECKOUT_COMMIT={sq(honcho_runtime["checkout_commit"])}', f'BOT_HONCHO_SUPERVISOR_LABEL={sq(honcho_runtime["supervisor_label"])}', f'BOT_HONCHO_EXPECTED_MEMORY_MODEL={sq(honcho_runtime["expected_memory_model"])}', f'BOT_INSTANCE_MANIFEST={sq(str(H/"instance.yaml"))}',
 f'BOT_AUTONOMY_POLICY_JSON={sq(json.dumps(autonomy_policy, sort_keys=True, separators=(",",":")))}',
 f'BOT_MISSION_OWNER_AUTHORED_DECLARED={sq("1" if flags["mission_owner_authored"] else "0")}', f'BOT_MISSION_OWNER_AUTHORED={sq("1" if posture["mission_complete"] else "0")}', f'BOT_MISSION_STATEMENT={sq(mission_statement)}', f'BOT_MISSION_ROADMAP_SOURCES_JSON={sq(json.dumps(mission_roadmap_sources, ensure_ascii=False))}', f'BOT_MISSION_OWNER_SIGNAL_POLICY={sq(mission_owner_signal_policy)}', f'BOT_MISSION_PERSONALITY_VOICE={sq(mission_personality_voice)}', f'BOT_MISSION_PERSONALITY_CREATIVE_POSTURE={sq(mission_personality_creative_posture)}', f'BOT_NPM_TAG={sq(npm_tag)}', f'BOT_PUBLISH_WORKFLOW={sq(publish_workflow)}',
 f'BOT_OMH_ENABLED={sq("1" if omh_enabled else "0")}', f'BOT_OMH_REQUIRED={sq("1" if omh_required else "0")}', f'BOT_OMH_HOME={sq(str(omh_home))}', f'BOT_OMH_SKILLS_SOURCE={sq(str(omh_skill_source))}',
 f'BOT_IMPLEMENTATION_MODE={sq(implementation_mode)}', f'BOT_IMPLEMENTATION_EXECUTOR={sq(implementation_executor)}', f'BOT_HERMES_DIRECT_FALLBACK={sq(hermes_direct_fallback)}',
 f'BOT_CODEX_HOME={sq(str(codex_home))}', f'BOT_CODEX_MODEL={sq(codex_model)}', f'BOT_CODEX_REASONING_EFFORT={sq(codex_reasoning_effort)}', f'BOT_CODEX_TIMEOUT_SECONDS={sq(codex_timeout_seconds)}', f'HERMES_PYTHON={sq(hermes_python)}', f'VIRTUAL_ENV={sq(hermes_venv)}',
 f'BOT_LEARNING_ENABLED={sq("1" if flags["learning_enabled"] else "0")}', f'BOT_LEARNING_CADENCE={sq(cron.get("learning_cadence") or learning.get("cadence") or "every 30m")}', f'BOT_LEARNING_STEWARD_PROFILE={sq(role_profiles["learning_steward"])}',
 f'BOT_OSC_PORTFOLIO_REQUESTED={sq("1" if posture["requested_portfolio_enabled"] else "0")}', f'BOT_OSC_PORTFOLIO_ENABLED={sq("1" if portfolio_enabled else "0")}', f'BOT_OSC_PORTFOLIO_CADENCE={sq(portfolio_cadence)}', f'BOT_OSC_PORTFOLIO_MAX_GAPS={sq(portfolio_max_gaps)}', f'BOT_OSC_PORTFOLIO_BRANCH_PREFIX={sq(portfolio_branch_prefix)}', f'BOT_OSC_PORTFOLIO_ISSUE_LABELS={sq(",".join(str(x) for x in as_list(portfolio_labels)))}',
]
for role,p in role_profiles.items(): script_lines.append(f'BOT_{role.upper()}_PROFILE={sq(p)}')
for k,v in sorted(runtime_imported.items()): script_lines.append(f'{k}={sq(v)}')
atomic_text(script_env, '\n'.join(script_lines).rstrip()+'\n', 0o600)
# profiles and templates
if not omh_enabled:
    root_cfg_path=H/'config.yaml'
    if root_cfg_path.exists() or root_cfg_path.is_symlink():
        root_cfg_info=root_cfg_path.lstat()
        if (root_cfg_path.is_symlink() or not stat.S_ISREG(root_cfg_info.st_mode)
                or root_cfg_info.st_uid!=os.geteuid() or root_cfg_info.st_nlink!=1
                or root_cfg_info.st_mode&0o022):
            raise SystemExit(f'unsafe root Hermes config metadata: {root_cfg_path}')
    root_cfg=yaml.safe_load(root_cfg_path.read_text(encoding='utf-8')) if root_cfg_path.exists() else {}
    root_cfg=root_cfg or {}
    root_memory=root_cfg.setdefault('memory', {})
    root_memory['memory_enabled']=False
    root_memory['user_profile_enabled']=False
    root_memory['provider']=''
    root_plugins=root_cfg.setdefault('plugins', {})
    root_enabled=[str(x) for x in root_plugins.get('enabled', [])]
    root_disabled=[str(x) for x in root_plugins.get('disabled', [])]
    root_plugins['enabled']=[x for x in root_enabled if x != 'omh']
    root_plugins['disabled']=list(dict.fromkeys([*root_disabled, 'omh']))
    root_entries=root_plugins.get('entries')
    if isinstance(root_entries, dict):
        root_entries.pop('omh', None)
    root_mcp=root_cfg.get('mcp_servers')
    if not isinstance(root_mcp, dict):
        root_mcp={}
        root_cfg['mcp_servers']=root_mcp
    root_mcp.pop('omh', None)
    platform_toolsets=root_cfg.get('platform_toolsets')
    if not isinstance(platform_toolsets, dict):
        platform_toolsets={}
        root_cfg['platform_toolsets']=platform_toolsets
    for toolsets in platform_toolsets.values():
        if isinstance(toolsets, list):
            toolsets[:]=[x for x in toolsets if x != 'omh']
    root_skills=root_cfg.setdefault('skills', {})
    root_external_dirs=root_skills.get('external_dirs')
    if isinstance(root_external_dirs, list):
        root_skills['external_dirs']=[x for x in root_external_dirs if not is_omh_external_dir(x)]
    atomic_text(root_cfg_path, yaml.safe_dump(root_cfg, sort_keys=False), 0o600)
    os.chmod(root_cfg_path,0o600)
    for generated in (omh_home, H/'plugins'/'omh'):
        if generated.is_dir() and not generated.is_symlink():
            shutil.rmtree(generated)
        elif generated.exists() or generated.is_symlink():
            generated.unlink()
for role, profile in role_profiles.items():
    pdir=H/'profiles'/profile
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir/'home').mkdir(parents=True, exist_ok=True)
    (pdir/'memories').mkdir(parents=True, exist_ok=True)
    plugins_dir=pdir/'plugins'
    if plugins_dir.is_symlink():
        raise SystemExit(f'unsafe profile plugin directory symlink: {plugins_dir}')
    plugins_dir.mkdir(parents=True, exist_ok=True)
    # Profile plugins are executable code. Clear stale assets and then install
    # only the product-owned hooks declared by the memory boundary contract.
    for stale_plugin in list(plugins_dir.iterdir()):
        if stale_plugin.is_dir() and not stale_plugin.is_symlink():
            shutil.rmtree(stale_plugin)
        else:
            stale_plugin.unlink()
    continuity_plugin_link=pdir/'plugins'/'john-lomein-continuity'
    continuity_plugin_link.symlink_to(
        H/'plugins'/'john-lomein-continuity',
        target_is_directory=True,
    )
    approval_plugin_link=pdir/'plugins'/'john-lomein-release-approval'
    if role == 'guide':
        approval_plugin_link.symlink_to(
            H/'plugins'/'john-lomein-release-approval',
            target_is_directory=True,
        )
        lifecycle_plugin_link=pdir/'plugins'/'john-lomein-guide-lifecycle'
        lifecycle_plugin_link.symlink_to(
            H/'plugins'/'john-lomein-guide-lifecycle',
            target_is_directory=True,
        )
    atomic_text(pdir/'.no-bundled-skills', 'john-lomein product runtime: bundled skills intentionally disabled; profile-local skills only.\n', 0o600)
    atomic_text(pdir/'SOUL.md', render((product/'profiles'/profile/'SOUL.md').read_text(encoding='utf-8')), 0o600)
    atomic_text(pdir/'memories'/'USER.md', f'john-lomein instance {slug}; fictional AI software-maintainer profile {profile}. No private owner memory. Hermes user-profile injection is disabled.\n', 0o600)
    atomic_text(pdir/'memories'/'MEMORY.md', 'Product-owned declarative reference only; Hermes agent memory, memory mutation, provider sync, and session recall are disabled. Truth comes from instance.yaml, SOUL, profile-local skills, GitHub, repo files/tests/CI, generated learning briefs, and this standalone runtime. Dynamic state remains canonical outside memory.\n', 0o600)
    profile_skills_root=pdir/'skills'
    if profile_skills_root.is_symlink():
        profile_skills_root.unlink()
    elif profile_skills_root.exists():
        shutil.rmtree(profile_skills_root)
    skills_root=profile_skills_root/'software-development'
    role_report={'local_skills':[], 'omh_skills_installed':[], 'omh_skills_missing':[]}
    for skill in role_skills[role]:
        dst=skills_root/skill/'SKILL.md'; atomic_text(dst, (product/'skills'/skill/'SKILL.md').read_text(encoding='utf-8'), 0o600)
        role_report['local_skills'].append(skill)
    if omh_enabled:
        for skill in role_omh_skills(role):
            omh_destination_root=profile_skills_root/'omh'
            src,dst=confined_omh_copy_paths(
                omh_skill_source,
                omh_destination_root,
                skill,
            )
            if not (src/'SKILL.md').exists():
                role_report['omh_skills_missing'].append(skill)
                continue
            validate_omh_source_tree(omh_skill_source, src)
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns('__pycache__','.git','.DS_Store'))
            write_normalized_skill(src/'SKILL.md', dst/'SKILL.md')
            role_report['omh_skills_installed'].append(skill)
    omh_report[role]=role_report
    # Profile model processes never receive Mnemosyne provider state. The
    # deterministic steward gets its data path from the runtime script env.
    # Only the public guide profile receives Discord tokens.
    managed_dir=managed_policy_directory(H, profile)
    if managed_dir.is_symlink():
        raise SystemExit(f'unsafe profile managed-policy directory: {managed_dir}')
    managed_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(managed_dir,0o700)
    managed_cfg=managed_dir/'config.yaml'
    if managed_cfg.exists() or managed_cfg.is_symlink():
        managed_stat=managed_cfg.lstat()
        if (
            managed_cfg.is_symlink()
            or not stat.S_ISREG(managed_stat.st_mode)
            or managed_stat.st_uid != os.geteuid()
            or managed_stat.st_nlink != 1
            or managed_stat.st_mode & 0o022
        ):
            raise SystemExit(f'unsafe profile managed-policy config: {managed_cfg}')
    atomic_text(managed_cfg, yaml.safe_dump(agent_memory_managed_policy(role), sort_keys=False), 0o600)
    penv=pdir/'.env'; env_lines=[f'HERMES_PYTHON={hermes_python}', f'VIRTUAL_ENV={hermes_venv}']
    profile_imported = (
        {
            k:v for k,v in imported.items()
            if not is_github_secret_key(k)
            and not is_runtime_control_key(k)
        }
        if role == 'guide'
        else runtime_imported
    )
    for k,v in sorted(profile_imported.items()): env_lines.append(f'{k}={v}')
    atomic_text(penv, '\n'.join(env_lines).rstrip()+'\n', 0o600)
    # A regular, later-sealed binding directory is populated after the runtime
    # script set is complete. Keeping the directory itself real lets the OS
    # sandbox protect it even while the surrounding profile root is writable.
    sl=pdir/'scripts'
    if sl.exists() or sl.is_symlink():
        if sl.is_dir() and not sl.is_symlink(): shutil.rmtree(sl)
        else: sl.unlink()
    sl.mkdir(mode=0o700)
    cfg_path=pdir/'config.yaml'
    if cfg_path.exists() or cfg_path.is_symlink():
        cfg_stat=cfg_path.lstat()
        if cfg_path.is_symlink() or not stat.S_ISREG(cfg_stat.st_mode):
            raise SystemExit(f'unsafe deployed profile config type: {cfg_path}')
        if cfg_stat.st_uid != os.geteuid() or cfg_stat.st_nlink != 1 or cfg_stat.st_mode & 0o022:
            raise SystemExit(f'unsafe deployed profile config metadata: {cfg_path}')
    cfg=yaml.safe_load(cfg_path.read_text(encoding='utf-8')) if cfg_path.exists() else {}
    cfg=cfg or {}
    cfg.setdefault('model', {})['provider']=model.get('provider') or 'openai-codex'
    cfg.setdefault('model', {})['default']=model.get('default') or model.get('model') or 'gpt-5.5'
    if role == 'maintainer':
        cfg.setdefault('agent', {})['max_turns']=450
    if model.get('reasoning_effort'):
        cfg.setdefault('agent', {})['reasoning_effort']=model.get('reasoning_effort')
    else:
        cfg.setdefault('agent', {})['reasoning_effort']='xhigh'
    if fallback.get('provider') and (fallback.get('model') or fallback.get('default')):
        cfg['fallback_providers']=[{'provider':fallback.get('provider'),'model':fallback.get('model') or fallback.get('default'),'reasoning_effort':fallback.get('reasoning_effort') or model.get('reasoning_effort') or 'xhigh'}]
    cfg.setdefault('terminal', {})['cwd']=local
    cfg.setdefault('terminal', {})['home_mode']='profile'
    cfg.setdefault('terminal', {})['dangerous_command_permanent_allowlist']=[]
    apply_agent_memory_boundary(cfg, role)
    skills_cfg=cfg.setdefault('skills', {})
    skills_cfg['write_approval']=True; skills_cfg['guard_agent_created']=True
    if not omh_enabled and isinstance(skills_cfg.get('external_dirs'), list):
        skills_cfg['external_dirs']=[x for x in skills_cfg['external_dirs'] if not is_omh_external_dir(x)]
    plugins_cfg=cfg.get('plugins')
    if not isinstance(plugins_cfg, dict):
        plugins_cfg={}
        cfg['plugins']=plugins_cfg
    enabled_plugins=plugins_cfg.get('enabled')
    disabled_plugins=plugins_cfg.get('disabled')
    enabled_plugins=[str(x) for x in enabled_plugins] if isinstance(enabled_plugins,list) else []
    disabled_plugins=[str(x) for x in disabled_plugins] if isinstance(disabled_plugins,list) else []
    if not omh_enabled:
        enabled_plugins=[x for x in enabled_plugins if x != 'omh']
        disabled_plugins=[x for x in disabled_plugins if x != 'omh']+['omh']
        profile_entries=plugins_cfg.get('entries')
        if isinstance(profile_entries, dict):
            profile_entries.pop('omh', None)
        profile_mcp=cfg.get('mcp_servers')
        if not isinstance(profile_mcp, dict):
            profile_mcp={}
            cfg['mcp_servers']=profile_mcp
        profile_mcp.pop('omh', None)
        profile_platform_toolsets=cfg.get('platform_toolsets')
        if not isinstance(profile_platform_toolsets, dict):
            profile_platform_toolsets={}
            cfg['platform_toolsets']=profile_platform_toolsets
        for toolsets in profile_platform_toolsets.values():
            if isinstance(toolsets, list):
                toolsets[:]=[x for x in toolsets if x != 'omh']
    continuity_plugin='john-lomein-continuity'
    enabled_plugins=[
        x for x in enabled_plugins if x != continuity_plugin
    ]+[continuity_plugin]
    disabled_plugins=[
        x for x in disabled_plugins if x != continuity_plugin
    ]
    approval_plugin='john-lomein-release-approval'
    if role == 'guide':
        enabled_plugins=[x for x in enabled_plugins if x != approval_plugin]+[approval_plugin]
        disabled_plugins=[x for x in disabled_plugins if x != approval_plugin]
    else:
        enabled_plugins=[x for x in enabled_plugins if x != approval_plugin]
        disabled_plugins=[x for x in disabled_plugins if x != approval_plugin]+[approval_plugin]
    lifecycle_plugin='john-lomein-guide-lifecycle'
    if role == 'guide':
        enabled_plugins=[x for x in enabled_plugins if x != lifecycle_plugin]+[lifecycle_plugin]
        disabled_plugins=[x for x in disabled_plugins if x != lifecycle_plugin]
    else:
        enabled_plugins=[x for x in enabled_plugins if x != lifecycle_plugin]
        disabled_plugins=[x for x in disabled_plugins if x != lifecycle_plugin]+[lifecycle_plugin]
    plugins_cfg['enabled']=list(dict.fromkeys(enabled_plugins))
    plugins_cfg['disabled']=list(dict.fromkeys(disabled_plugins))
    cfg.setdefault('approvals', {})['mode']='manual'; cfg.setdefault('approvals', {})['cron_mode']='deny'; cfg.setdefault('approvals', {})['destructive_slash_confirm']=True
    cfg.setdefault('agent', {})['bot_mode_protocol']=collaboration['bot_chat_protocol_enabled']
    cfg['command_allowlist']=[]
    cfg.setdefault('security', {})['redact_secrets']=True; cfg.setdefault('security', {})['tirith_enabled']=True; cfg.setdefault('security', {})['allow_private_urls']=False
    delegation_cfg=cfg.setdefault('delegation', {})
    delegation_cfg['subagent_auto_approve']=False
    atomic_text(cfg_path, yaml.safe_dump(cfg, sort_keys=False), 0o600)
    os.chmod(cfg_path,0o600)
    write_profile_honcho_config(
        bot,
        instance_slug=slug,
        role=role,
        profile=profile,
        profile_home=pdir,
    )
    pause_file=H/'state'/'honcho'/'INGESTION_PAUSED.json'
    if role=='guide' and pause_file.exists():
        honcho_path=pdir/'honcho.json'
        honcho_payload=json.loads(honcho_path.read_text(encoding='utf-8'))
        hosts=honcho_payload.get('hosts')
        if not isinstance(hosts,dict) or not hosts or any(not isinstance(host,dict) for host in hosts.values()):
            raise SystemExit('invalid Guide Honcho hosts while preserving pause')
        for host in hosts.values():
            host['saveMessages']=False
        atomic_text(honcho_path, json.dumps(honcho_payload, indent=2, sort_keys=True)+'\n', 0o600)
        os.chmod(honcho_path,0o600)
atomic_text(H/'state'/'john-lomein-persona.json', json.dumps({
    'schema_version':'john_lomein_persona_deployment/v1',
    'persona_version':persona_version,
    'sha256':persona_sha256,
    'source':'persona/JOHN_LOMEIN.md',
    'profiles':role_profiles,
}, indent=2, sort_keys=True), 0o600)
os.chmod(H/'state'/'john-lomein-persona.json', 0o600)
initialize_store(H/'state'/'continuity')
atomic_text(H/'state'/'john-lomein-autonomy-policy.json', json.dumps({
    'schema_version':'john-lomein.autonomy-deployment.v1',
    'policy':autonomy_policy,
    'policy_sha256':hashlib.sha256(json.dumps(autonomy_policy, sort_keys=True, separators=(',',':')).encode('utf-8')).hexdigest(),
}, indent=2, sort_keys=True), 0o600)
collaboration_state={**collaboration}
collaboration_state['policy_sha256']=hashlib.sha256(
    json.dumps(collaboration, sort_keys=True, separators=(',',':')).encode('utf-8')
).hexdigest()
atomic_text(H/'state'/'john-lomein-collaboration-policy.json',
    json.dumps(collaboration_state, indent=2, sort_keys=True),
    0o600,
)
os.chmod(H/'state'/'john-lomein-collaboration-policy.json', 0o600)
atomic_text(H/'state'/'john-lomein-review-quorum-policy.json',
    json.dumps(review_quorum, indent=2, sort_keys=True),
    0o600,
)
os.chmod(H/'state'/'john-lomein-review-quorum-policy.json', 0o600)
atomic_text(H/'state'/'john-lomein-native-workflows.json', json.dumps({
    'schema_version':'john-lomein.native-workflows.v1',
    'native_skill':'john-lomein-native-workflows',
    'implementation_mode':implementation_mode,
    'implementation_executor':implementation_executor,
    'legacy_omh':{
        'enabled':omh_enabled,
        'required':omh_required,
        'omh_home':str(omh_home),
        'skill_source':str(omh_skill_source),
        'roles':omh_report,
    },
}, indent=2, sort_keys=True), 0o600)
# copy scripts
script_names=[
    'john_lomein_auth_projection.py',
    'john_lomein_autonomy.py',
    'john_lomein_collaboration_contract.py',
    'john_lomein_comment_templates.py',
    'john_lomein_container_verifier.py',
    'john_lomein_continuity.py',
    'john_lomein_continuity_importer.py',
    'john_lomein_continuity_protocol.py',
    'john_lomein_factory_receipts.py',
    'john_lomein_file_contract.py',
    'john_lomein_gateway_lock_contract.py',
    'john_lomein_guide_lifecycle.py',
    'john_lomein_guide_runtime_preflight.py',
    'john_lomein_proposal.py',
    'john_lomein_manifest_contract.py',
    'john_lomein_honcho_contract.py',
    'john_lomein_honcho_pilot.py',
    'john_lomein_honcho_broker.py',
    'john_lomein_public_honcho_service.py',
    'john_lomein_memory_boundary_migration.py',
    'john_lomein_memory_contract.py',
    'john_lomein_model_isolation.py',
    'john_lomein_provider_broker.py',
    'john_lomein_provider_bootstrap.py',
    'john_lomein_owner_actions.py',
    'john_lomein_plugin_contract.py',
    'john_lomein_profile_contract.py',
    'john_lomein_protected_actions.py',
    'john_lomein_public_safety.py',
    'john_lomein_release_packets.py',
    'john_lomein_scoped_publication.py',
    'john_lomein_service_registry.py',
    'john-lomein-continuity-hook-canary.py',
    'john-lomein-factory-simulate.py',
    'john-lomein-trust-assertion.py',
    'john-lomein-auth-env.sh',
    'john-lomein-diagnostic-tick.sh',
    'john-lomein-watchdog.sh',
    'john-lomein-maintainer-trigger.sh',
    'john-lomein-maintainer-prompt.txt',
    'john-lomein-worker.py',
    'john-lomein-gh-guard.py',
    'john-lomein-git-guard.py',
    'john-lomein-protected-submit.py',
    'john-lomein-issue-intake.py',
    'john-lomein-issue-triage.py',
    'john-lomein-osc-portfolio-steward.py',
    'john-lomein-osc-portfolio-trigger.sh',
    'john-lomein-release-approve.py',
    'john-lomein-release-bundler.py',
    'john-lomein-release-executor.py',
    'john-lomein-release-submit.py',
    'john-lomein-forge-trigger.sh',
    'john-lomein-forge-orchestrator.py',
    'john-lomein-omh-implementation.py',
    'john-lomein-queue-health.py',
    'john-lomein-cross-instance-learning-digest.py',
    'john-lomein-learning-steward.py',
    'john-lomein-learning-trigger.sh',
    'john-lomein-overwatch-trigger.sh',
    'john-lomein-overwatch-scan.py',
    'john-lomein-overwatch-post.sh',
    'john-lomein-overwatch-prompt.txt',
    'john-lomein-keepawake.sh',
    'install-runtime-supervisor.sh',
    'uninstall-runtime-supervisor.sh',
    'repair-profile-gh-auth.py',
    'stage_profile_distribution.py',
    'read-instance-env.py',
    'apply-guide-discord-config.py',
    'install-guide-gateway.sh',
    'john_lomein_owner_override.py',
    'john_lomein_review_quorum.py',
    'honcho-embedding-recovery-candidates.sql',
    'honcho-participant-candidates.sql',
    'honcho-participant-delete.sql',
    'honcho-retention-candidates.sql',
    'honcho-retention-delete.sql',
    'john-lomein-honcho-watchdog.py',
    'john-lomein-honcho-watchdog.sh',
    'john-lomein-exact-head-review.py',
]
if not omh_enabled:
    script_names=[name for name in script_names if name != 'john-lomein-omh-implementation.py']
allowed_script_entries={
    *script_names,
    'john-lomein-instance.env',
    'release_broker',
    'bin',
}
for stale in list((H/'scripts').iterdir()):
    if stale.name in allowed_script_entries:
        continue
    if stale.is_dir() and not stale.is_symlink():
        shutil.rmtree(stale)
    else:
        stale.unlink()
for name in script_names:
    src=product/'scripts'/name; dst=H/'scripts'/name
    atomic_text(dst, src.read_text(encoding='utf-8'), 0o600 if name.endswith('.txt') else 0o755)
release_client_package=H/'scripts'/'release_broker'
if release_client_package.exists():
    shutil.rmtree(release_client_package)
release_client_package.mkdir(mode=0o700)
for name in [
    '__init__.py',
    'john_lomein_release_broker_protocol.py',
    'john_lomein_release_broker_receipts.py',
]:
    src=product/'release_broker'/name
    dst=release_client_package/name
    atomic_text(dst, src.read_text(encoding='utf-8'), 0o600)
approval_plugin_source=product/'runtime_plugins'/'john-lomein-release-approval'
approval_plugin_destination=H/'plugins'/'john-lomein-release-approval'
if approval_plugin_destination.is_symlink():
    raise SystemExit(
        f'unsafe deployed release approval plugin path: {approval_plugin_destination}'
    )
if approval_plugin_destination.exists():
    shutil.rmtree(approval_plugin_destination)
shutil.copytree(
    approval_plugin_source,
    approval_plugin_destination,
    ignore=shutil.ignore_patterns('__pycache__','.DS_Store'),
)
os.chmod(approval_plugin_destination, 0o700)
for plugin_file in approval_plugin_destination.iterdir():
    if plugin_file.is_symlink() or not plugin_file.is_file():
        raise SystemExit(
            f'unsafe release approval plugin asset: {plugin_file}'
        )
    os.chmod(plugin_file, 0o600)
continuity_plugin_source=product/'runtime_plugins'/'john-lomein-continuity'
continuity_plugin_destination=H/'plugins'/'john-lomein-continuity'
if continuity_plugin_destination.is_symlink():
    raise SystemExit(
        f'unsafe deployed continuity plugin path: {continuity_plugin_destination}'
    )
if continuity_plugin_destination.exists():
    shutil.rmtree(continuity_plugin_destination)
shutil.copytree(
    continuity_plugin_source,
    continuity_plugin_destination,
    ignore=shutil.ignore_patterns('__pycache__','.DS_Store'),
)
os.chmod(continuity_plugin_destination, 0o700)
for plugin_file in continuity_plugin_destination.iterdir():
    if plugin_file.is_symlink() or not plugin_file.is_file():
        raise SystemExit(
            f'unsafe continuity plugin asset: {plugin_file}'
        )
    os.chmod(plugin_file, 0o600)
guide_lifecycle_plugin_source=product/'runtime_plugins'/'john-lomein-guide-lifecycle'
guide_lifecycle_plugin_destination=H/'plugins'/'john-lomein-guide-lifecycle'
if guide_lifecycle_plugin_destination.is_symlink():
    raise SystemExit(
        f'unsafe deployed Guide lifecycle plugin path: {guide_lifecycle_plugin_destination}'
    )
if guide_lifecycle_plugin_destination.exists():
    shutil.rmtree(guide_lifecycle_plugin_destination)
shutil.copytree(
    guide_lifecycle_plugin_source,
    guide_lifecycle_plugin_destination,
    ignore=shutil.ignore_patterns('__pycache__','.DS_Store'),
)
os.chmod(guide_lifecycle_plugin_destination, 0o700)
for plugin_file in guide_lifecycle_plugin_destination.iterdir():
    if plugin_file.is_symlink() or not plugin_file.is_file():
        raise SystemExit(
            f'unsafe Guide lifecycle plugin asset: {plugin_file}'
        )
    os.chmod(plugin_file, 0o600)
# `gh` guard: put a wrapper ahead of the real gh in worker PATH so maintainer
# profile commands cannot spam duplicate @codex review requests for a head that
# already has a clean Codex artifact or a request in flight.
guard_bin = H/'scripts'/'bin'
if guard_bin.is_symlink():
    raise SystemExit(f'unsafe runtime guard directory: {guard_bin}')
if guard_bin.exists():
    shutil.rmtree(guard_bin)
guard_bin.mkdir(parents=True, mode=0o700)
wrapper = guard_bin/'gh'
atomic_text(wrapper, '#!/usr/bin/env bash\nexec "$(dirname "$0")/../john-lomein-gh-guard.py" "$@"\n', 0o755)
git_wrapper = guard_bin/'git'
atomic_text(git_wrapper, '#!/usr/bin/env bash\nexec "$(dirname "$0")/../john-lomein-git-guard.py" "$@"\n', 0o755)

# Mirror the exact completed runtime script set into each profile through a
# real sealed directory. Hermes rejects per-file aliases as cron traversal, so
# the protected mirror is deliberate rather than a writable compatibility link.
for profile in role_profiles.values():
    bindings=H/'profiles'/profile/'scripts'
    if bindings.is_symlink() or not bindings.is_dir():
        raise SystemExit(f'unsafe profile script binding root: {bindings}')
    for stale in list(bindings.iterdir()):
        if stale.is_dir() and not stale.is_symlink():
            shutil.rmtree(stale)
        else:
            stale.unlink()
    shutil.copytree(
        H/'scripts',
        bindings,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns('__pycache__','.DS_Store'),
    )
    os.chmod(bindings, 0o700)
PY
}

install_profile_distribution() {
  local configured_profile="$1" distribution="$2"
  local staged="$BOT_HERMES_HOME/distributions/$distribution"
  if ! "${PRODUCT_PYTHON[@]}" "$PRODUCT_ROOT/scripts/stage_profile_distribution.py" "$PRODUCT_ROOT" "$BOT_HERMES_HOME" "$distribution" "$configured_profile" >/dev/null; then
    echo "failed to stage rendered Hermes profile distribution: $distribution" >&2
    return 2
  fi
  if ! HERMES_HOME="$BOT_HERMES_HOME" \
    hermes profile install "$staged" --name "$configured_profile" --force -y >/dev/null
  then
    echo "failed to install required Hermes profile distribution: $distribution -> $configured_profile" >&2
    return 2
  fi
  echo "profile distribution installed: $distribution -> $configured_profile"
}

# Render all instance identities and configs before any distribution install.
# Staging then copies only already-rendered SOULs, so a later install failure
# cannot leave unresolved identity templates in live profiles.
render_and_configure
install_profile_distribution "$BOT_MAINTAINER_PROFILE" john-lomein-maintainer
install_profile_distribution "$BOT_FORGE_PROFILE" john-lomein-forge
install_profile_distribution "$BOT_GUIDE_PROFILE" john-lomein-guide
install_profile_distribution "$BOT_OVERWATCH_PROFILE" john-lomein-overwatch
install_profile_distribution "$BOT_LEARNING_STEWARD_PROFILE" john-lomein-learning-steward
if ! HERMES_HOME="$BOT_HERMES_HOME" hermes config migrate </dev/null >/dev/null; then
  echo "failed to migrate root Hermes config" >&2
  exit 2
fi
for profile in "$BOT_MAINTAINER_PROFILE" "$BOT_FORGE_PROFILE" "$BOT_GUIDE_PROFILE" "$BOT_OVERWATCH_PROFILE" "$BOT_LEARNING_STEWARD_PROFILE"; do
  if ! HERMES_HOME="$BOT_HERMES_HOME" hermes -p "$profile" config migrate </dev/null >/dev/null; then
    echo "failed to migrate Hermes profile config: $profile" >&2
    exit 2
  fi
done
# Use the freshly generated instance env for deploy-time credential scrubbing,
# cron/profile setup, and lane-specific knobs not exposed at bootstrap.
. "$BOT_HERMES_HOME/scripts/john-lomein-instance.env"
if [ "${BOT_GUIDE_GATEWAY_ENABLED:-0}" = "1" ]; then
  "${PRODUCT_PYTHON[@]}" \
    "$BOT_HERMES_HOME/scripts/john_lomein_public_honcho_service.py" \
    public-service-install \
    --manifest "$BOT_HERMES_HOME/instance.yaml" >/dev/null
fi
if [ "${BOT_MODEL_PROVIDER:-}" = "openai-codex" ] || [ "${BOT_FALLBACK_PROVIDER:-}" = "openai-codex" ]; then
  "$HERMES_PYTHON" "$BOT_HERMES_HOME/scripts/john_lomein_auth_projection.py" scrub \
    --runtime-home "$BOT_HERMES_HOME" \
    --provider openai-codex \
    --profile "$BOT_HERMES_HOME/profiles/$BOT_MAINTAINER_PROFILE" \
    --profile "$BOT_HERMES_HOME/profiles/$BOT_FORGE_PROFILE" \
    --profile "$BOT_HERMES_HOME/profiles/$BOT_GUIDE_PROFILE" \
    --profile "$BOT_HERMES_HOME/profiles/$BOT_OVERWATCH_PROFILE" \
    --profile "$BOT_HERMES_HOME/profiles/$BOT_LEARNING_STEWARD_PROFILE" \
    --quiet
fi
if ! continuity_canary_output="$(
  "${PRODUCT_PYTHON[@]}" \
    "$PRODUCT_ROOT/scripts/john-lomein-continuity-hook-canary.py" \
    --hermes "$(command -v hermes)" \
    --asset-root "$BOT_HERMES_HOME" \
    --timeout 45 2>&1
)"; then
  echo "deployed continuity hook canary failed:" >&2
  printf '%s\n' "$continuity_canary_output" >&2
  exit 2
fi
if ! guide_config_output="$(
  "${PRODUCT_PYTHON[@]}" \
    "$PRODUCT_ROOT/scripts/apply-guide-discord-config.py" \
    "$JL_INSTANCE_MANIFEST_INPUT" 2>&1
)"; then
  echo "guide Discord config application failed:" >&2
  printf '%s\n' "$guide_config_output" >&2
  exit 2
fi
# Export non-interactive gh/git auth before any deploy-time GitHub work.
. "$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"

setup_omh_bridge() {
  "${PRODUCT_PYTHON[@]}" - "$BOT_HERMES_HOME" "${BOT_OMH_HOME:-$BOT_HERMES_HOME/omh}" "${BOT_IMPLEMENTATION_EXECUTOR:-codex}" "${BOT_OMH_ENABLED:-1}" "${BOT_OMH_REQUIRED:-0}" <<'PY'
from __future__ import annotations
import json, os, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path

home = Path(sys.argv[1]).expanduser().resolve()
omh_home = Path(sys.argv[2]).expanduser().resolve()
executor = (sys.argv[3] or "codex").strip()
enabled = sys.argv[4] == "1"
required = sys.argv[5] == "1"
state = home / "state"
state.mkdir(parents=True, exist_ok=True)
report_path = state / "john-lomein-omh-bridge.json"
report = {
    "schema_version": "john_lomein_omh_bridge_setup/v1",
    "enabled": enabled,
    "required": required,
    "hermes_home": str(home),
    "omh_home": str(omh_home),
    "implementation_executor": executor,
    "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "steps": {},
}

def atomic_text(path: Path, text: str, mode: int = 0o600) -> None:
    fd, temporary = tempfile.mkstemp(prefix='.deploy-', dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)

def finish(status: str, code: int = 0) -> None:
    report["status"] = status
    report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    atomic_text(report_path, json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(code)

def write_step_file(name: str, suffix: str, text: str) -> str:
    path = state / f"john-lomein-omh-bridge-{name}.{suffix}"
    atomic_text(path, text or "")
    return str(path)

def run_step(name: str, cmd: list[str], *, input_text: str | None = None, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.update({
        "HERMES_HOME": str(home),
        "JOHN_LOMEIN_INSTANCE_HERMES_HOME": str(home),
        "JOHN_LOMEIN_HERMES_HOME": str(home),
        "OMH_HOME": str(omh_home),
    })
    env.pop("MNEMOSYNE_DATA_DIR", None)
    try:
        proc = subprocess.run(cmd, input=input_text, capture_output=True, text=True, env=env, timeout=timeout)
    except Exception as exc:
        proc = subprocess.CompletedProcess(cmd, 999, "", str(exc))
    report["steps"][name] = {
        "cmd": cmd,
        "exit_code": proc.returncode,
        "stdout": write_step_file(name, "out", proc.stdout),
        "stderr": write_step_file(name, "err", proc.stderr),
    }
    return proc

if not enabled:
    finish("disabled")

omh = shutil.which("omh")
hermes = shutil.which("hermes")
report["commands"] = {"omh": omh, "hermes": hermes}
if not omh:
    finish("missing_omh", 2 if required else 0)
if not hermes:
    finish("missing_hermes", 2 if required else 0)

allowed_executors = {"choose", "codex", "claude-code", "omc-runtime", "generic", "hermes"}
default_executor = executor if executor in allowed_executors else "codex"
setup = run_step(
    "setup",
    [omh, "--omh-home", str(omh_home), "--hermes-home", str(home), "setup", "--full", "--yes", "--no-interactive", "--default-executor", default_executor, "--force", "--with-mcp", "--json"],
    timeout=300,
)
plugin = run_step("plugin-enable", [hermes, "plugins", "enable", "omh"], timeout=120)
mcp_before = run_step("mcp-list-before", [hermes, "mcp", "list"], timeout=60)
if not re.search(r"(?m)^\s*omh\s", mcp_before.stdout or ""):
    run_step(
        "mcp-add",
        [hermes, "mcp", "add", "omh", "--command", omh, "--args", "--omh-home", str(omh_home), "--hermes-home", str(home), "mcp", "serve"],
        input_text="y\n",
        timeout=180,
    )
mcp_after = run_step("mcp-list-after", [hermes, "mcp", "list"], timeout=60)
ok = setup.returncode == 0 and plugin.returncode == 0 and re.search(r"(?m)^\s*omh\s", mcp_after.stdout or "")
finish("configured" if ok else "degraded", 2 if required and not ok else 0)
PY
}

setup_omh_bridge

# OMH setup populates the instance-local skill source after the initial profile
# render. Project only the exact per-role allow-list into each profile now,
# without consulting or modifying the user's personal ~/.omh state.
"${PRODUCT_PYTHON[@]}" - \
  "$PRODUCT_ROOT" \
  "$BOT_HERMES_HOME" \
  "$BOT_OMH_HOME" \
  "$BOT_OMH_REQUIRED" <<'PY'
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import sys
from pathlib import Path, PurePosixPath

product = Path(sys.argv[1])
home = Path(sys.argv[2])
omh_home = Path(sys.argv[3])
required = sys.argv[4] == "1"
sys.path.insert(0, str(product / "scripts"))

from john_lomein_manifest_contract import (  # noqa: E402
    confined_omh_copy_paths,
    validate_omh_source_tree,
)

report_path = home / "state" / "john-lomein-native-workflows.json"
report = json.loads(report_path.read_text(encoding="utf-8"))
legacy_omh = report.get("legacy_omh")
roles = legacy_omh.get("roles") if isinstance(legacy_omh, dict) else report.get("roles")
if not isinstance(roles, dict):
    raise SystemExit("OMH role projection report is invalid")
source_root = (omh_home / "skills").resolve()
if not source_root.is_dir():
    if required:
        raise SystemExit(
            f"required instance-local OMH skill source is missing: {source_root}"
        )
    raise SystemExit(0)

catalog_path = omh_home / "manifest.json"
try:
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise SystemExit(f"invalid instance-local OMH manifest: {exc}") from exc
catalog_entries = catalog.get("skills")
if not isinstance(catalog_entries, list):
    raise SystemExit("instance-local OMH manifest has no skill catalog")
catalog_sources: dict[str, str] = {}
for entry in catalog_entries:
    if not isinstance(entry, dict):
        raise SystemExit("instance-local OMH manifest skill entry is invalid")
    name = entry.get("name")
    raw_path = entry.get("path")
    if not isinstance(name, str) or not isinstance(raw_path, str):
        raise SystemExit("instance-local OMH manifest skill metadata is invalid")
    relative = PurePosixPath(raw_path)
    if (
        relative.is_absolute()
        or len(relative.parts) != 2
        or relative.parts[1] != "SKILL.md"
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise SystemExit(f"unsafe instance-local OMH skill path: {raw_path}")
    if name in catalog_sources:
        raise SystemExit(f"duplicate instance-local OMH skill: {name}")
    catalog_sources[name] = relative.parts[0]


def normalize_skill_frontmatter_text(text: str) -> str:
    if not text.startswith("---"):
        return text
    end = text.find("\n---", 3)
    if end < 0:
        return text
    front = text[3:end]
    body = text[end + len("\n---"):]
    lines: list[str] = []
    changed = False
    for line in front.splitlines():
        match = re.match(r"^(description:\s*)(.+?)\s*$", line)
        if match:
            value = match.group(2).strip()
            if value and not value.startswith(('"', "'", "|", ">")):
                line = match.group(1) + json.dumps(value)
                changed = True
        lines.append(line)
    if not changed:
        return text
    return "---\n" + "\n".join(lines).rstrip() + "\n---" + body


desired_by_role: dict[str, list[str]] = {}
validated_sources: dict[str, Path] = {}
for role, role_report in roles.items():
    if not isinstance(role_report, dict):
        raise SystemExit(f"OMH role projection is invalid: {role}")
    desired = sorted(
        {
            str(skill)
            for key in ("omh_skills_installed", "omh_skills_missing")
            for skill in (role_report.get(key) or [])
        }
    )
    desired_by_role[str(role)] = desired
    for skill in desired:
        source_component = catalog_sources.get(skill)
        if source_component is None:
            if required:
                raise SystemExit(
                    f"required instance-local OMH skill is missing: {skill}"
                )
            continue
        source, _ = confined_omh_copy_paths(
            source_root,
            home / "state" / ".omh-validation",
            skill,
            source_component=source_component,
        )
        if not (source / "SKILL.md").is_file():
            if required:
                raise SystemExit(
                    f"required instance-local OMH skill is missing: {skill}"
                )
            continue
        validate_omh_source_tree(source_root, source)
        validated_sources[skill] = source
validation_root = home / "state" / ".omh-validation"
if validation_root.is_symlink():
    raise SystemExit("unsafe OMH validation root")
if validation_root.exists():
    shutil.rmtree(validation_root)

for role, role_report in roles.items():
    profile = {
        "maintainer": "john-lomein-maintainer",
        "forge": "john-lomein-forge",
        "guide": "john-lomein-guide",
        "overwatch": "john-lomein-overwatch",
        "learning_steward": "john-lomein-learning-steward",
    }.get(str(role))
    if profile is None:
        raise SystemExit(f"unknown OMH projection role: {role}")
    skills_root = home / "profiles" / profile / "skills"
    destination = skills_root / "omh"
    staging = skills_root / ".omh-staging"
    for path in (destination, staging):
        if path.is_symlink():
            raise SystemExit(f"unsafe OMH profile projection path: {path}")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(mode=0o700)
    installed: list[str] = []
    missing: list[str] = []
    for skill in desired_by_role[str(role)]:
        source = validated_sources.get(skill)
        if source is None:
            missing.append(skill)
            continue
        target = staging / skill
        shutil.copytree(
            source,
            target,
            ignore=shutil.ignore_patterns("__pycache__", ".git", ".DS_Store"),
        )
        skill_file = target / "SKILL.md"
        atomic_text(
            skill_file,
            normalize_skill_frontmatter_text(skill_file.read_text(encoding="utf-8")),
        )
        installed.append(skill)
    for directory, names, files in os.walk(staging, followlinks=False):
        current = Path(directory)
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise SystemExit(f"unsafe OMH projected directory: {current}")
        os.chmod(current, 0o700)
        for name in [*names, *files]:
            path = current / name
            if path.is_symlink():
                raise SystemExit(f"unsafe OMH projected symlink: {path}")
            if path.is_file():
                os.chmod(path, 0o600)
    if destination.exists():
        shutil.rmtree(destination)
    staging.replace(destination)
    role_report["omh_skills_installed"] = installed
    role_report["omh_skills_missing"] = missing

report["skill_source"] = str(source_root)
atomic_text(report_path, json.dumps(report, indent=2, sort_keys=True))
PY

# toolset bounding after configs exist
for profile in "$BOT_MAINTAINER_PROFILE" "$BOT_FORGE_PROFILE" "$BOT_GUIDE_PROFILE" "$BOT_OVERWATCH_PROFILE" "$BOT_LEARNING_STEWARD_PROFILE"; do
  profile_managed_dir="$BOT_HERMES_MANAGED_ROOT/$profile"
  HERMES_HOME="$BOT_HERMES_HOME" HERMES_MANAGED_DIR="$profile_managed_dir" hermes -p "$profile" skills opt-out --remove --yes >/dev/null 2>&1 || true
  for ts in web terminal file skills todo; do
    HERMES_HOME="$BOT_HERMES_HOME" HERMES_MANAGED_DIR="$profile_managed_dir" hermes -p "$profile" tools enable "$ts" >/dev/null 2>&1 || true
  done
  for ts in memory session_search browser vision image_gen video_gen video tts moa clarify delegation cronjob homeassistant spotify yuanbao computer_use x_search code_execution context_engine; do
    HERMES_HOME="$BOT_HERMES_HOME" HERMES_MANAGED_DIR="$profile_managed_dir" hermes -p "$profile" tools disable "$ts" >/dev/null 2>&1 || true
  done
done
for ts in terminal file context_engine delegation; do
  HERMES_HOME="$BOT_HERMES_HOME" HERMES_MANAGED_DIR="$BOT_HERMES_MANAGED_ROOT/$BOT_GUIDE_PROFILE" hermes -p "$BOT_GUIDE_PROFILE" tools disable "$ts" >/dev/null 2>&1 || true
done
# Hermes' tool commands intentionally rewrite platform lists and may remove the
# no_mcp sentinel. Reassert the raw contract after all CLI migrations. The
# higher-precedence policy remains independently pinned and exact.
"${PRODUCT_PYTHON[@]}" - "$PRODUCT_ROOT" "$JL_INSTANCE_MANIFEST_INPUT" "$BOT_HERMES_HOME" <<'PY'
from pathlib import Path
import os, stat, sys, tempfile
import yaml

product = Path(sys.argv[1])
manifest = Path(sys.argv[2])
home = Path(sys.argv[3])
sys.path.insert(0, str(product / "scripts"))
from john_lomein_collaboration_contract import collaboration_policy
from john_lomein_manifest_contract import manifest_boolean_flags
from john_lomein_memory_contract import apply_agent_memory_boundary
from john_lomein_plugin_contract import apply_product_plugin_boundary
from john_lomein_profile_contract import canonical_role_profiles

def atomic_text(path: Path, text: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix='.deploy-', dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)

bot = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
omh_enabled = manifest_boolean_flags(bot)["omh_enabled"]
collaboration = collaboration_policy(bot)
for role, profile in canonical_role_profiles(bot).items():
    path = home / "profiles" / profile / "config.yaml"
    info = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o022
    ):
        raise SystemExit(f"unsafe profile config before boundary reassertion: {path}")
    config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(config, dict):
        raise SystemExit(f"invalid profile config before boundary reassertion: {path}")
    apply_agent_memory_boundary(config, role)
    apply_product_plugin_boundary(config, role, omh_enabled=omh_enabled)
    product_plugins={
        'john-lomein-continuity',
        *(
            {
                'john-lomein-release-approval',
                'john-lomein-guide-lifecycle',
            }
            if role=='guide'
            else set()
        ),
    }
    bindings=home/'profiles'/profile/'plugins'
    if bindings.is_symlink() or not bindings.is_dir():
        raise SystemExit(f'unsafe profile plugin binding root: {bindings}')
    for plugin_name in (
        'john-lomein-continuity',
        'john-lomein-release-approval',
        'john-lomein-guide-lifecycle',
    ):
        binding=bindings/plugin_name
        expected=home/'plugins'/plugin_name
        if plugin_name in product_plugins:
            if binding.exists() or binding.is_symlink():
                if not binding.is_symlink() or binding.resolve()!=expected.resolve():
                    raise SystemExit(f'unsafe profile plugin binding: {binding}')
            else:
                binding.symlink_to(expected,target_is_directory=True)
        elif binding.exists() or binding.is_symlink():
            if binding.is_dir() and not binding.is_symlink():
                raise SystemExit(f'unsafe non-Guide product plugin directory: {binding}')
            binding.unlink()
    config.setdefault("agent", {})["bot_mode_protocol"] = collaboration[
        "bot_chat_protocol_enabled"
    ]
    atomic_text(path, yaml.safe_dump(config, sort_keys=False))
PY

if [ ! -d "$BOT_LOCAL/.git" ]; then
  mkdir -p "$(dirname "$BOT_LOCAL")"
  git clone "https://github.com/$BOT_REPO.git" "$BOT_LOCAL" >/dev/null
fi
git -C "$BOT_LOCAL" fetch --prune origin >/dev/null
# Some bounded executor wrappers write private runtime residue into the managed
# checkout (for example `.clawhip/state/prompt-submit.json`). That residue is
# never repo truth and should not keep the appliance from refreshing main.
if [ -e "$BOT_LOCAL/.clawhip" ] && [ -z "$(git -C "$BOT_LOCAL" ls-files -- .clawhip 2>/dev/null)" ]; then
  rm -rf "$BOT_LOCAL/.clawhip"
fi
if [ -n "$(git -C "$BOT_LOCAL" status --porcelain)" ]; then
  echo "managed checkout dirty; skipped checkout/pull: $BOT_LOCAL" >&2
else
  git -C "$BOT_LOCAL" checkout "$BOT_DEFAULT_BRANCH" >/dev/null
  git -C "$BOT_LOCAL" pull --ff-only origin "$BOT_DEFAULT_BRANCH" >/dev/null
fi

"${PRODUCT_PYTHON[@]}" "$PRODUCT_ROOT/scripts/repair-profile-gh-auth.py" "$JL_INSTANCE_MANIFEST_INPUT" --quiet || true

"${PRODUCT_PYTHON[@]}" - "$BOT_HERMES_HOME" "$BOT_MAINTAINER_PROFILE" "$BOT_SLUG" <<'PY'
import os, re, subprocess, sys
home, profile, slug = sys.argv[1:4]
env=dict(
    os.environ,
    HERMES_HOME=home,
    JOHN_LOMEIN_INSTANCE_HERMES_HOME=home,
    HERMES_MANAGED_DIR=os.path.join(home,'managed-policy',profile),
)
env.pop('MNEMOSYNE_DATA_DIR',None)
base=['hermes','-p',profile,'cron']
out=subprocess.run(base+['list','--all'],capture_output=True,text=True,env=env).stdout
cur=None; remove=[]
for line in out.splitlines():
    m=re.match(r'^\s*([0-9a-f]{8,})\s+\[', line)
    if m: cur=m.group(1)
    m=re.match(r'^\s*Name:\s+(.*)', line)
    if m and cur and m.group(1).strip().startswith(f'john-lomein-{slug}-'):
        remove.append(cur)
for jid in remove:
    subprocess.run(base+['remove',jid],capture_output=True,text=True,env=env)
PY
create_product_cron() {
  local cadence="$1" script="$2" name="$3" create_output list_output
  if ! create_output="$(
    HERMES_HOME="$BOT_HERMES_HOME" \
      HERMES_MANAGED_DIR="$BOT_HERMES_MANAGED_ROOT/$BOT_MAINTAINER_PROFILE" \
      hermes -p "$BOT_MAINTAINER_PROFILE" cron create "$cadence" \
        --no-agent --script "$script" --name "$name" \
        --deliver "$BOT_DELIVER" 2>&1
  )"; then
    echo "failed to create required instance cron: $name" >&2
    printf '%s\n' "$create_output" >&2
    return 2
  fi
  list_output="$(
    HERMES_HOME="$BOT_HERMES_HOME" \
      HERMES_MANAGED_DIR="$BOT_HERMES_MANAGED_ROOT/$BOT_MAINTAINER_PROFILE" \
      hermes -p "$BOT_MAINTAINER_PROFILE" cron list --all 2>&1
  )"
  if ! grep -Fq "$name" <<<"$list_output"; then
    echo "Hermes reported success without persisting required cron: $name" >&2
    printf '%s\n' "$create_output" >&2
    return 2
  fi
}
if [ "${BOT_MUTATION_ENABLED:-0}" = "1" ]; then
  create_product_cron "$BOT_WATCHDOG_CADENCE" john-lomein-watchdog.sh "john-lomein-$BOT_SLUG-watchdog"
  create_product_cron "$BOT_MAINTAINER_CADENCE" john-lomein-maintainer-trigger.sh "john-lomein-$BOT_SLUG-maintainer"
  create_product_cron "$BOT_FORGE_CADENCE" john-lomein-forge-trigger.sh "john-lomein-$BOT_SLUG-forge-cycle"
  create_product_cron "$BOT_OVERWATCH_CADENCE" john-lomein-overwatch-trigger.sh "john-lomein-$BOT_SLUG-overwatch"
  if [ "${BOT_LEARNING_ENABLED:-1}" = "1" ]; then
    create_product_cron "$BOT_LEARNING_CADENCE" john-lomein-learning-trigger.sh "john-lomein-$BOT_SLUG-learning-steward"
  fi
  if [ "${BOT_OSC_PORTFOLIO_ENABLED:-0}" = "1" ]; then
    create_product_cron "$BOT_OSC_PORTFOLIO_CADENCE" john-lomein-osc-portfolio-trigger.sh "john-lomein-$BOT_SLUG-osc-portfolio"
  fi
fi
if [ "${BOT_HONCHO_WATCHDOG_ENABLED:-0}" = "1" ] && [ "${BOT_GUIDE_GATEWAY_ENABLED:-0}" = "1" ]; then
  create_product_cron "every 5m" john-lomein-honcho-watchdog.sh "john-lomein-$BOT_SLUG-honcho-watchdog"
fi
# External Hermes/OMH administrative commands can initialize their historical
# default path even though agent memory is disabled. Sweep again after every
# such command and preserve any residue in the model-hidden quarantine.
"${PRODUCT_PYTHON[@]}" \
  "$PRODUCT_ROOT/scripts/john_lomein_memory_boundary_migration.py" \
  --runtime-home "$BOT_HERMES_HOME" \
  --private-root "$BOT_STEWARD_PRIVATE_ROOT" \
  --projection-root "$BOT_STEWARD_PROJECTION_ROOT" \
  --quiet

verify_deploy_manifest
echo "deploy complete: $BOT_DISPLAY_NAME -> $BOT_REPO"
echo "runtime: $BOT_HERMES_HOME"
echo "profiles: $BOT_MAINTAINER_PROFILE,$BOT_FORGE_PROFILE,$BOT_GUIDE_PROFILE,$BOT_OVERWATCH_PROFILE,$BOT_LEARNING_STEWARD_PROFILE"
echo "activation=$BOT_ACTIVATION mutation=$BOT_MUTATION_ENABLED discord=$BOT_DISCORD_ENABLED"
