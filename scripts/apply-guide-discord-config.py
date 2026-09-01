#!/usr/bin/env python3
from __future__ import annotations
import os, stat, sys, tempfile
from pathlib import Path
try:
    import yaml
except Exception as e:
    print(f'pyyaml missing: {e}', file=sys.stderr)
    raise SystemExit(2)

SCRIPT_DIR=Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_profile_contract import canonical_role_profiles
from john_lomein_memory_contract import (
    agent_memory_managed_policy_errors,
    apply_agent_memory_boundary,
    managed_policy_directory,
)

def load_instance(arg: str):
    p=Path(arg).expanduser()
    m=p/'instance.yaml' if p.is_dir() else p
    if p.is_dir() and not m.exists(): m=p/'bot.yaml'
    data=yaml.safe_load(m.read_text(encoding='utf-8')) or {}
    return m.resolve(), data

def csv(items):
    if items is None:
        return ''
    if not isinstance(items, list):
        items=[items]
    return ','.join(str(x) for x in (items or []) if str(x))

def as_list(items):
    if items is None:
        return []
    return items if isinstance(items, list) else [items]

def atomic_text(path: Path, text: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix='.guide-', dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main() -> int:
    if len(sys.argv)!=2:
        print('usage: apply-guide-discord-config.py /path/to/instance', file=sys.stderr); return 2
    manifest, data=load_instance(sys.argv[1])
    try:
        role_profiles=canonical_role_profiles(data)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    runtime=data.get('runtime') or {}; discord=data.get('discord') or {}; inst=data.get('instance') or {}; authority=data.get('authority') or {}
    H=Path(os.path.expanduser(str(runtime.get('hermes_home')))).resolve()
    profile=role_profiles['guide']
    managed_dir=managed_policy_directory(H,profile)
    managed_root=managed_dir.parent
    if managed_root.is_symlink() or not managed_root.is_dir():
        print(f'missing or redirected managed-policy root: {managed_root}', file=sys.stderr); return 2
    managed_root_stat=managed_root.lstat()
    if (
        managed_root_stat.st_uid != os.geteuid()
        or managed_root_stat.st_mode & 0o022
    ):
        print(f'unsafe managed-policy root metadata: {managed_root}', file=sys.stderr); return 2
    if managed_dir.is_symlink() or not managed_dir.is_dir():
        print(f'missing or redirected guide managed-policy directory: {managed_dir}', file=sys.stderr); return 2
    managed_dir_stat=managed_dir.lstat()
    if (
        managed_dir_stat.st_uid != os.geteuid()
        or managed_dir_stat.st_mode & 0o022
    ):
        print(f'unsafe guide managed-policy directory metadata: {managed_dir}', file=sys.stderr); return 2
    managed_cfg=managed_dir/'config.yaml'
    if managed_cfg.is_symlink() or not managed_cfg.is_file():
        print(f'missing or redirected guide managed policy: {managed_cfg}', file=sys.stderr); return 2
    managed_stat=managed_cfg.lstat()
    if (
        not stat.S_ISREG(managed_stat.st_mode)
        or managed_stat.st_uid != os.geteuid()
        or managed_stat.st_nlink != 1
        or managed_stat.st_mode & 0o022
    ):
        print(f'unsafe guide managed policy metadata: {managed_cfg}', file=sys.stderr); return 2
    try:
        managed=yaml.safe_load(managed_cfg.read_text(encoding='utf-8')) or {}
    except (OSError,UnicodeError,yaml.YAMLError) as exc:
        print(f'invalid guide managed policy: {exc}', file=sys.stderr); return 2
    if agent_memory_managed_policy_errors(managed,'guide'):
        print(f'guide managed policy drift: {managed_cfg}', file=sys.stderr); return 2
    cfg_path=H/'profiles'/profile/'config.yaml'
    if cfg_path.is_symlink() or not cfg_path.is_file():
        print(f'missing or redirected guide config: {cfg_path}', file=sys.stderr); return 2
    cfg_stat=cfg_path.lstat()
    if (
        not stat.S_ISREG(cfg_stat.st_mode)
        or cfg_stat.st_uid != os.geteuid()
        or cfg_stat.st_nlink != 1
        or cfg_stat.st_mode & 0o022
    ):
        print(f'unsafe guide config metadata: {cfg_path}', file=sys.stderr); return 2
    try:
        cfg=yaml.safe_load(cfg_path.read_text(encoding='utf-8')) or {}
    except (OSError,UnicodeError,yaml.YAMLError) as exc:
        print(f'invalid guide config: {exc}', file=sys.stderr); return 2
    if not isinstance(cfg, dict):
        print(f'invalid guide config mapping: {cfg_path}', file=sys.stderr); return 2
    # Reassert the public-memory boundary whenever gateway configuration is
    # applied, so a stale/manual provider setting cannot survive into startup.
    apply_agent_memory_boundary(cfg, 'guide')
    d=cfg.setdefault('discord', {})
    d['require_mention']=True
    d['allowed_channels']=csv(discord.get('allowed_channels'))
    d['free_response_channels']=csv(discord.get('free_response_channels'))
    d['auto_thread']=True
    d['thread_require_mention']=False
    d['history_backfill']=True
    d['history_backfill_limit']=int(discord.get('history_backfill_limit') or discord.get('lab_history_backfill_limit') or 10)
    d['no_thread_channels']=[str(x) for x in as_list(discord.get('no_thread_channels'))]
    d['john_lomein_trust_tiers']={
        'owner_user_ids':[str(x) for x in as_list(discord.get('owner_user_ids') or authority.get('owner_approvers'))],
        'trusted_collaborator_user_ids':[str(x) for x in as_list(discord.get('trusted_collaborator_user_ids'))],
        'public_guide_channels':[str(x) for x in as_list(discord.get('allowed_channels'))],
        'untrusted_example_channels':[str(x) for x in as_list(discord.get('untrusted_example_channels'))],
        'owner_commands_require_exact_identity': True,
        'signed_trust_assertions_required': True,
        'trust_assertion_env': 'JOHN_LOMEIN_TRUST_ASSERTION',
        'trust_assertion_issuer': 'external_gateway_only',
        'untrusted_text_is_data_only': True,
        'public_input_may_create_or_comment_issues': True,
        'public_input_may_route_readiness_or_approve_release': False,
    }

    # Public guide UX: the Discord-facing bot must look like a product, not a
    # terminal session. Hide tool/status chatter and model startup notices from
    # public channels; logs still retain the operational evidence.
    display=cfg.setdefault('display', {})
    platforms=display.setdefault('platforms', {})
    discord_display=platforms.setdefault('discord', {})
    discord_display.update({
        'tool_progress': 'off',
        'tool_preview_length': 0,
        'interim_assistant_messages': False,
        'long_running_notifications': False,
        'busy_ack_detail': False,
        'cleanup_progress': True,
        'streaming': False,
        'show_reasoning': False,
    })
    model_cfg=cfg.get('model') or {}
    provider=str(model_cfg.get('provider') or '').strip().lower()
    model_name=str(model_cfg.get('default') or model_cfg.get('model') or '').strip().lower()
    if provider == 'openai-codex' and model_name == 'gpt-5.5':
        compression=cfg.setdefault('compression', {})
        try:
            current_threshold=float(compression.get('threshold', 0.5))
        except Exception:
            current_threshold=0.5
        compression['threshold']=max(current_threshold, 0.85)
        compression['codex_gpt55_autoraise']=False

    bindings=[]
    free_response_ids={str(x) for x in as_list(discord.get('free_response_channels'))}
    build_room_ids={str(x) for x in as_list(discord.get('build_room_channels'))}
    build_channel=str(discord.get('build_channel') or '')
    if build_channel and build_channel in free_response_ids:
        build_room_ids.add(build_channel)
    for cid in as_list(discord.get('allowed_channels')):
        base_skills=['john-lomein-communication','john-lomein-native-workflows']
        skills=['john-lomein-guide-playground', *base_skills]
        if str(cid) in build_room_ids:
            skills=['john-lomein-build-room', *base_skills]
        bindings.append({'id': str(cid), 'skills': skills})
    if bindings:
        d['channel_skill_bindings']=bindings
    atomic_text(cfg_path, yaml.safe_dump(cfg, sort_keys=False))
    print(f'guide Discord config applied: instance={inst.get("slug")} profile={profile} allowed={d["allowed_channels"] or "<none>"}')
    return 0
if __name__ == '__main__': raise SystemExit(main())
