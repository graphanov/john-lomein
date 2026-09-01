#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, os, shlex, sys
import stat
from pathlib import Path
try:
    import yaml
except Exception as e:
    print(f"pyyaml missing: {e}", file=sys.stderr)
    raise SystemExit(2)

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_factory_receipts import (
    safe_authority_level,
    safe_default_branch,
    safe_github_repo,
    safe_instance_slug,
    safe_npm_tag,
    safe_publish_workflow,
    safe_runtime_activation,
    public_metadata_text,
)
from john_lomein_manifest_contract import (
    effective_authority_posture,
    validate_manifest_contract,
    validate_runtime_checkout_separation,
)
from john_lomein_profile_contract import canonical_role_profiles
from john_lomein_file_contract import StableFileError, read_stable_regular

MAX_MANIFEST_BYTES = 1024 * 1024
SETUP_SNAPSHOT_ENV = 'JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT'
SETUP_SOURCE_ENV = 'JOHN_LOMEIN_SETUP_MANIFEST_SOURCE'
SETUP_SHA256_ENV = 'JOHN_LOMEIN_SETUP_MANIFEST_SHA256'


def _normal_paths(arg: str) -> tuple[Path, Path]:
    p = Path(arg).expanduser()
    try:
        supplied_info = p.lstat()
    except FileNotFoundError:
        supplied_info = None
    except OSError as exc:
        raise SystemExit('instance manifest path is unreadable') from exc
    if supplied_info is not None and stat.S_ISLNK(supplied_info.st_mode):
        raise SystemExit('instance manifest path is unsafe')
    if supplied_info is not None and stat.S_ISDIR(supplied_info.st_mode):
        primary = p / 'instance.yaml'
        legacy = p / 'bot.yaml'
        present = {}
        for candidate in (primary, legacy):
            try:
                candidate.lstat()
                present[candidate] = True
            except FileNotFoundError:
                present[candidate] = False
            except OSError as exc:
                raise SystemExit(
                    'instance manifest path is unreadable'
                ) from exc
        if present[primary] and present[legacy]:
            raise SystemExit(
                'instance has more than one authoritative manifest candidate'
            )
        y = primary if present[primary] else legacy
    else:
        y = p
        p = y.parent
    try:
        y.lstat()
    except FileNotFoundError as exc:
        raise SystemExit('missing instance manifest') from exc
    except OSError as exc:
        raise SystemExit('instance manifest path is unreadable') from exc
    return Path(os.path.abspath(p)), Path(os.path.abspath(y))


def _setup_paths(arg: str, source_raw: str) -> tuple[Path, Path]:
    source = Path(source_raw).expanduser()
    if not source.is_absolute():
        raise SystemExit('setup manifest source binding must be absolute')
    source = Path(os.path.abspath(source))
    supplied = Path(os.path.abspath(Path(arg).expanduser()))
    if supplied not in {source, source.parent}:
        raise SystemExit('setup manifest source binding does not match instance')
    if source.name not in {'instance.yaml', 'bot.yaml'}:
        raise SystemExit('setup manifest source binding is invalid')
    return source.parent, source


def _read_setup_snapshot(path_raw: str, expected_sha256: str) -> tuple[Path, bytes]:
    if (
        len(expected_sha256) != 64
        or any(character not in '0123456789abcdef' for character in expected_sha256)
    ):
        raise SystemExit('setup manifest digest binding is invalid')
    path = Path(path_raw).expanduser()
    if not path.is_absolute():
        raise SystemExit('setup manifest snapshot binding must be absolute')
    path = Path(os.path.abspath(path))
    try:
        raw = read_stable_regular(
            path,
            maximum_bytes=MAX_MANIFEST_BYTES,
            owner_only=True,
        )
    except StableFileError as exc:
        raise SystemExit(
            f'setup manifest snapshot stable read failed: {exc.code}'
        ) from exc
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise SystemExit('setup manifest snapshot digest mismatch')
    return path, raw


def load_instance(arg: str) -> tuple[Path, Path, Path, dict]:
    snapshot_raw = os.environ.get(SETUP_SNAPSHOT_ENV, '')
    source_raw = os.environ.get(SETUP_SOURCE_ENV, '')
    expected_sha256 = os.environ.get(SETUP_SHA256_ENV, '')
    setup_values = (snapshot_raw, source_raw, expected_sha256)
    if any(setup_values) and not all(setup_values):
        raise SystemExit('setup manifest binding is incomplete')
    if all(setup_values):
        idir, manifest = _setup_paths(arg, source_raw)
        manifest_input, raw = _read_setup_snapshot(
            snapshot_raw,
            expected_sha256,
        )
    else:
        idir, manifest = _normal_paths(arg)
        manifest_input = manifest
        try:
            raw = read_stable_regular(
                manifest,
                maximum_bytes=MAX_MANIFEST_BYTES,
                owner_only=True,
            )
        except StableFileError as exc:
            raise SystemExit(
                f'instance manifest stable read failed: {exc.code}'
            ) from exc
    try:
        data = yaml.safe_load(raw.decode('utf-8')) or {}
    except (UnicodeError, yaml.YAMLError) as exc:
        raise SystemExit('instance manifest is invalid') from exc
    return idir, manifest, manifest_input, data

def q(value) -> str:
    return shlex.quote(str(value if value is not None else ''))

def seq(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]

def safe_slug(value) -> str:
    try:
        return safe_instance_slug(value)
    except ValueError as exc:
        raise SystemExit(f'unsafe instance.slug: {str(value or "<empty>")}') from exc


def main() -> int:
    if len(sys.argv) != 2:
        print('usage: read-instance-env.py /path/to/instance-or-manifest', file=sys.stderr)
        return 2
    idir, manifest, manifest_input, data = load_instance(sys.argv[1])
    inst = data.get('instance') or {}
    mission = data.get('mission') or {}
    target = data.get('target') or {}
    runtime = data.get('runtime') or {}
    profiles = data.get('profiles') or {}
    model = data.get('model') or {}
    fallback = model.get('fallback') or {}
    authority = data.get('authority') or {}
    gates = data.get('gates') or {}
    parallel = data.get('parallel_lanes') or {}
    workflows = data.get('workflows') or {}
    learning = data.get('learning') or {}
    forge = data.get('forge') or {}
    cron = data.get('cron') or {}
    discord = data.get('discord') or {}
    release = data.get('release') or {}
    try:
        contract = validate_manifest_contract(data)
        role_profiles = canonical_role_profiles(data)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    flags = contract['flags']
    posture = effective_authority_posture(data, contract=contract)
    autonomy_policy = contract['autonomy']
    mission_fields = contract['prompt']['mission']
    autonomous_safe_labels = contract['prompt']['gates']['autonomous_safe_labels']
    slug = safe_slug(inst.get('slug') or data.get('slug'))
    try:
        display = public_metadata_text(inst.get('display_name'), 'instance.display_name', slug, max_length=160)
        repo = safe_github_repo(target.get('repo'))
        branch = safe_default_branch(target.get('default_branch'))
        requested_activation = safe_runtime_activation(runtime.get('activation'))
        maintainer_level = safe_authority_level(authority.get('maintainer_level'), 'authority.maintainer_level', '2')
        forge_level = safe_authority_level(authority.get('forge_level'), 'authority.forge_level', '1')
        guide_level = safe_authority_level(authority.get('guide_level'), 'authority.guide_level', '1')
        overwatch_level = safe_authority_level(authority.get('overwatch_level'), 'authority.overwatch_level', '1.5')
        npm_tag = safe_npm_tag(release.get('npm_tag'))
        publish_workflow = safe_publish_workflow(release.get('publish_workflow'))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if requested_activation != posture['requested_activation']:
        raise SystemExit('runtime activation projection is inconsistent')
    local = Path(os.path.expanduser(str(target.get('local_checkout') or target.get('local') or f'~/.john-lomein/instances/{slug}/work/repo')))
    home = Path(os.path.expanduser(str(runtime.get('hermes_home') or f'~/.john-lomein/instances/{slug}/hermes')))
    try:
        local, home = validate_runtime_checkout_separation(local, home)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    omh_home = Path(os.path.expanduser(str(workflows.get('omh_home') or (home / 'omh')))).resolve()
    codex_home = Path(os.path.expanduser(str(workflows.get('codex_home') or os.environ.get('CODEX_HOME') or (Path.home() / '.codex')))).resolve()
    values = {
        'JL_INSTANCE_DIR': idir,
        'JL_INSTANCE_MANIFEST': manifest,
        'JL_INSTANCE_MANIFEST_INPUT': manifest_input,
        'BOT_SLUG': slug,
        'BOT_DISPLAY_NAME': display,
        'BOT_NAME': 'john-lomein',
        # Mission fields are intentionally limited to the public-safe card.
        # Trust identities, credentials, and private operator context are not
        # exported through this bootstrap surface.
        'BOT_MISSION_OWNER_AUTHORED_DECLARED': (
            '1' if flags['mission_owner_authored'] else '0'
        ),
        'BOT_MISSION_OWNER_AUTHORED': (
            '1' if posture['mission_complete'] else '0'
        ),
        'BOT_MISSION_COMPLETE': '1' if posture['mission_complete'] else '0',
        'BOT_MISSION_STATEMENT': mission_fields['statement'],
        'BOT_MISSION_ROADMAP_SOURCES_JSON': json.dumps(mission_fields['roadmap_sources'], ensure_ascii=False),
        'BOT_MISSION_OWNER_SIGNAL_POLICY': mission_fields['owner_signal_policy'],
        'BOT_MISSION_PERSONALITY_VOICE': mission_fields['voice'],
        'BOT_MISSION_PERSONALITY_CREATIVE_POSTURE': mission_fields['creative_posture'],
        'BOT_REPO': repo,
        'BOT_DEFAULT_BRANCH': branch,
        'BOT_LOCAL': local,
        'BOT_HERMES_HOME': home,
        'BOT_HERMES_MANAGED_ROOT': home / 'managed-policy',
        'BOT_MODEL_MEMORY_ISOLATION': contract['model_memory_isolation'],
        'BOT_STEWARD_PRIVATE_ROOT': home / 'private' / 'learning-steward',
        'BOT_STEWARD_PROJECTION_ROOT': home / 'state' / 'learning',
        'BOT_REQUESTED_ACTIVATION': posture['requested_activation'],
        'BOT_ACTIVATION': posture['activation'],
        'BOT_MUTATION_REQUESTED': (
            '1' if posture['requested_mutation_enabled'] else '0'
        ),
        'BOT_MUTATION_ENABLED': '1' if posture['mutation_enabled'] else '0',
        'BOT_DISCORD_REQUESTED': (
            '1' if posture['requested_discord_enabled'] else '0'
        ),
        'BOT_DISCORD_ENABLED': '1' if posture['discord_enabled'] else '0',
        'BOT_GUIDE_GATEWAY_REQUESTED': (
            '1' if posture['requested_guide_gateway_enabled'] else '0'
        ),
        'BOT_GUIDE_GATEWAY_ENABLED': (
            '1' if posture['guide_gateway_enabled'] else '0'
        ),
        'BOT_PROTECTED_RELEASE_BROKER_REQUESTED': (
            '1'
            if posture['requested_protected_release_broker_enabled']
            else '0'
        ),
        'BOT_PROTECTED_RELEASE_BROKER_ENABLED': (
            '1' if posture['protected_release_broker_enabled'] else '0'
        ),
        'BOT_OSC_PORTFOLIO_REQUESTED': (
            '1' if posture['requested_portfolio_enabled'] else '0'
        ),
        'BOT_OSC_PORTFOLIO_ENABLED': (
            '1' if posture['portfolio_enabled'] else '0'
        ),
        'BOT_KEEP_AWAKE_ON_AC': '1' if flags['runtime_keep_awake_on_ac'] else '0',
        'BOT_AUTONOMY_POLICY_JSON': json.dumps(
            autonomy_policy,
            sort_keys=True,
            separators=(',', ':'),
        ),
        'BOT_AUTONOMOUS_SAFE_LABELS': ','.join(autonomous_safe_labels),
        'BOT_MAINTAINER_PROFILE': role_profiles['maintainer'],
        'BOT_FORGE_PROFILE': role_profiles['forge'],
        'BOT_GUIDE_PROFILE': role_profiles['guide'],
        'BOT_OVERWATCH_PROFILE': role_profiles['overwatch'],
        'BOT_LEARNING_STEWARD_PROFILE': role_profiles['learning_steward'],
        'BOT_MODEL_PROVIDER': model.get('provider') or 'openai-codex',
        'BOT_MODEL_DEFAULT': model.get('default') or model.get('model') or 'gpt-5.5',
        'BOT_REASONING_EFFORT': model.get('reasoning_effort') or 'xhigh',
        'BOT_FALLBACK_PROVIDER': fallback.get('provider') or '',
        'BOT_FALLBACK_MODEL': fallback.get('model') or fallback.get('default') or '',
        'BOT_FALLBACK_REASONING_EFFORT': fallback.get('reasoning_effort') or model.get('reasoning_effort') or 'xhigh',
        'BOT_OMH_ENABLED': '1' if flags['omh_enabled'] else '0',
        'BOT_OMH_REQUIRED': '1' if flags['omh_required'] else '0',
        'BOT_OMH_HOME': omh_home,
        'BOT_IMPLEMENTATION_MODE': workflows.get('implementation_mode') or 'hermes_direct',
        'BOT_IMPLEMENTATION_EXECUTOR': workflows.get('implementation_executor') or 'codex',
        'BOT_HERMES_DIRECT_FALLBACK': workflows.get('hermes_direct_fallback') or 'blocked_only',
        'BOT_CODEX_HOME': codex_home,
        'BOT_CODEX_MODEL': workflows.get('codex_model') or model.get('default') or model.get('model') or 'gpt-5.5',
        'BOT_CODEX_REASONING_EFFORT': workflows.get('codex_reasoning_effort') or model.get('reasoning_effort') or 'xhigh',
        'BOT_CODEX_TIMEOUT_SECONDS': workflows.get('codex_timeout_seconds') or 3600,
        'BOT_MAINTAINER_LEVEL': maintainer_level,
        'BOT_FORGE_LEVEL': forge_level,
        'BOT_GUIDE_LEVEL': guide_level,
        'BOT_OVERWATCH_LEVEL': overwatch_level,
        'BOT_NPM_TAG': npm_tag,
        'BOT_PUBLISH_WORKFLOW': publish_workflow,
        'BOT_OWNER_APPROVERS': ','.join(str(x) for x in seq(authority.get('owner_approvers') or discord.get('owner_user_ids'))),
        'BOT_TRUST_PUBLIC_KEY_SHA256': authority.get('trust_public_key_sha256') or discord.get('trust_public_key_sha256') or '',
        'BOT_DISCORD_OWNER_USER_IDS': ','.join(str(x) for x in seq(discord.get('owner_user_ids'))),
        'BOT_DISCORD_TRUSTED_COLLABORATOR_USER_IDS': ','.join(str(x) for x in seq(discord.get('trusted_collaborator_user_ids'))),
        'BOT_DISCORD_UNTRUSTED_EXAMPLE_CHANNELS': ','.join(str(x) for x in seq(discord.get('untrusted_example_channels'))),
        'BOT_TEST_CMD': gates.get('test_cmd') or '',
        'BOT_FORBIDDEN_PATHS_JSON': json.dumps(
            gates.get('forbidden_paths') or [],
            separators=(',', ':'),
        ),
        'BOT_WATCHDOG_CADENCE': cron.get('watchdog_cadence') or 'every 7m',
        'BOT_MAINTAINER_CADENCE': cron.get('maintainer_cadence') or 'every 2m',
        'BOT_FORGE_CADENCE': cron.get('forge_cadence') or 'every 15m',
        'BOT_OVERWATCH_CADENCE': cron.get('overwatch_cadence') or 'every 5m',
        'BOT_LEARNING_CADENCE': cron.get('learning_cadence') or learning.get('cadence') or 'every 30m',
        'BOT_LEARNING_ENABLED': '1' if flags['learning_enabled'] else '0',
        'BOT_DELIVER': cron.get('deliver') or 'local',
        'BOT_MAX_OPEN_TOTAL_PRS': parallel.get('max_open_total_prs') or 4,
        'BOT_MAX_OPEN_BOT_PRS': parallel.get('max_open_bot_prs') or 3,
        'BOT_MAX_OPEN_FORGE_PRS': parallel.get('max_open_forge_prs') or 2,
        'BOT_FORGE_IN_CYCLE_REVISE_MAX_ROUNDS': forge.get('in_cycle_revise_max_rounds') or 2,
        'BOT_FORGE_REVISE_RETRY_AFTER_SECONDS': forge.get('revise_retry_after_seconds') or 1800,
        'BOT_FORGE_REVISE_MAX_RETRIES': forge.get('revise_max_retries') or 3,
        'BOT_ALLOWED_CHANNELS': ','.join(str(x) for x in (discord.get('allowed_channels') or [])),
        'BOT_FREE_RESPONSE_CHANNELS': ','.join(str(x) for x in (discord.get('free_response_channels') or [])),
        'BOT_NO_THREAD_CHANNELS': ','.join(str(x) for x in (discord.get('no_thread_channels') or [])),
        'BOT_BUILD_CHANNEL': discord.get('build_channel') or '',
        'BOT_PLAYGROUND_CHANNEL': discord.get('playground_channel') or '',
        'BOT_FORGE_CHANNEL': discord.get('forge_channel') or '',
        'BOT_NOTIFICATIONS_CHANNEL': discord.get('bot_notifications_channel') or discord.get('build_channel') or '',
        'BOT_ANNOUNCEMENTS_CHANNEL': discord.get('announcements_channel') or '',
    }
    for k, v in values.items():
        print(f'{k}={q(v)}')
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
