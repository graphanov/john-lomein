#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, os, plistlib, re, shutil, stat, subprocess, sys
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[1]
SCRIPT_DIR=Path(__file__).resolve().parent
PERSONA_PATH=ROOT/'persona'/'JOHN_LOMEIN.md'
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_owner_actions import DIRTY_CHECKOUT_RECOVERY, split_csv
from john_lomein_factory_receipts import (
    MISSION_PERSONALITY_CREATIVE_POSTURE,
    MISSION_PERSONALITY_VOICE,
    prompt_data,
    public_metadata_text,
    safe_authority_level,
    safe_default_branch,
    safe_github_repo,
    safe_instance_slug,
    safe_npm_tag,
    safe_publish_workflow,
    safe_runtime_activation,
)
from john_lomein_manifest_contract import (
    effective_authority_posture,
    manifest_boolean_flags,
    omh_catalog_skill_sources,
    validate_manifest_contract,
    validate_runtime_checkout_separation,
    validated_omh_skills_by_role,
    validated_public_prompt_fields,
)
from john_lomein_memory_contract import (
    DISABLED_AGENT_MEMORY_TOOLSETS,
    MNEMOSYNE_PLUGIN,
    agent_memory_boundary_errors,
    agent_memory_managed_policy_errors,
    managed_policy_directory,
)
from john_lomein_honcho_contract import (
    honcho_settings,
    probe_honcho_health,
    profile_honcho_errors,
)
from john_lomein_gateway_lock_contract import (
    GatewayLockContractError,
    gateway_lock_root,
    validate_gateway_lock_root,
)
from john_lomein_model_isolation import run_isolation_canary
from john_lomein_auth_projection import (
    AuthProjectionError,
    verify_projection as verify_auth_projection,
)
from john_lomein_continuity import ContinuityError, verify_store as verify_continuity_store
from john_lomein_continuity_importer import (
    ContinuityImporterError,
    status as continuity_import_status,
    verify_runtime as verify_continuity_import,
)
from john_lomein_continuity_protocol import ContinuityProtocolError
from john_lomein_profile_contract import canonical_role_profiles
from john_lomein_persona_contract import load_persona_core
from john_lomein_service_registry import registry_status
from john_lomein_collaboration_contract import collaboration_policy
from john_lomein_autonomy import (
    AutonomyError,
    autonomy_status,
    sha256_json,
)
FAIL=[]; WARN=[]
DEFAULT_OMH_SKILLS={
 'maintainer':['oh-my-hermes','code-review','ultrawork','ultraqa','deploy-and-monitor','agent-ops-review'],
 'forge':['oh-my-hermes','ralplan','deep-interview','ultrawork','code-review','ultraqa'],
 'guide':['oh-my-hermes','deep-interview','ralplan','source-finder'],
 'overwatch':['oh-my-hermes','agent-ops-review','code-review','ultraqa','doctor'],
 'learning_steward':['oh-my-hermes','workflow-learning','memory-sync','agent-ops-review','doctor'],
}
def note(level,msg):
    if level=='FAIL': FAIL.append(msg)
    if level=='WARN': WARN.append(msg)
    print(f'[{level}] {msg}')

def safe_runtime_directory(path):
    try:
        info=path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode) and not path.is_symlink() and info.st_uid==os.geteuid() and not (info.st_mode & 0o022)

def safe_runtime_public_key(path):
    try:
        info=path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_uid==os.geteuid() and info.st_nlink==1 and not (info.st_mode & 0o022)
def diagnostic_exit_code():
    return 2 if FAIL else (1 if WARN else 0)
def mission_authority_level(*,mission_complete,mission_public_safe,authority_requested):
    if mission_complete:
        return 'OK'
    if not mission_public_safe or authority_requested:
        return 'FAIL'
    return 'WARN'
def authority_projection_evidence(posture):
    requested={
        'activation':posture['requested_activation'],
        'mutation':bool(posture['requested_mutation_enabled']),
        'discord':bool(posture['requested_discord_enabled']),
        'guide_gateway':bool(posture['requested_guide_gateway_enabled']),
        'protected_release':bool(posture['requested_protected_release_broker_enabled']),
        'portfolio':bool(posture['requested_portfolio_enabled']),
    }
    effective={
        'activation':posture['activation'],
        'mutation':bool(posture['mutation_enabled']),
        'discord':bool(posture['discord_enabled']),
        'guide_gateway':bool(posture['guide_gateway_enabled']),
        'protected_release':bool(posture['protected_release_broker_enabled']),
        'portfolio':bool(posture['portfolio_enabled']),
    }
    effective['scheduler_required']=(
        effective['activation']=='active' or effective['mutation']
    )
    effective['guide_required']=(
        effective['discord'] and effective['guide_gateway']
    )
    return {'requested':requested,'effective':effective}
def sh(cmd,cwd=None,env=None,timeout=45):
    e=dict(os.environ)
    if env: e.update(env)
    home=Path(e.get('BOT_HERMES_HOME') or e.get('HERMES_HOME') or '')
    profile=e.get('BOT_MAINTAINER_PROFILE') or 'john-lomein-maintainer'
    gh_config=home/'profiles'/profile/'home'/'.config'/'gh'
    if home and gh_config.exists():
        e.setdefault('GH_CONFIG_DIR', str(gh_config))
    e.setdefault('GH_PROMPT_DISABLED','1')
    e.setdefault('GH_NO_UPDATE_NOTIFIER','1')
    e.setdefault('GH_NO_EXTENSION_UPDATE_NOTIFIER','1')
    try:
        r=subprocess.run(cmd,cwd=str(cwd) if cwd else None,capture_output=True,text=True,timeout=timeout,env=e)
        return r.returncode,r.stdout.strip(),r.stderr.strip()
    except Exception as ex:
        return 999,'',str(ex)
def protected_qualification_doctor(slug,command_root=Path('/usr/local/bin')):
    command=Path(command_root)/f'john-lomein-persona-qualification-doctor-{slug}'
    if not command.exists() and not command.is_symlink():
        note('WARN','protected persona qualification doctor is not installed; operator attestation remains unavailable')
        return
    try:
        info=command.lstat()
    except OSError as exc:
        note('FAIL',f'protected persona qualification doctor metadata is unreadable: {exc}')
        return
    metadata_ok=(
        stat.S_ISREG(info.st_mode)
        and not command.is_symlink()
        and info.st_uid==0
        and info.st_gid==0
        and stat.S_IMODE(info.st_mode)==0o555
        and info.st_nlink==1
    )
    if not metadata_ok:
        note(
            'FAIL',
            'protected persona qualification doctor is not an exact root:wheel 0555 single-link regular file',
        )
        return
    clean_env={
        'HOME':'/var/empty',
        'LANG':'C',
        'LC_ALL':'C',
        'PATH':'/usr/bin:/bin:/usr/sbin:/sbin',
        'TMPDIR':'/private/tmp',
        'TZ':'UTC',
    }
    try:
        result=subprocess.run(
            [str(command)],
            cwd='/',
            env=clean_env,
            close_fds=True,
            capture_output=True,
            text=False,
            timeout=10,
            check=False,
        )
    except Exception as exc:
        note('FAIL',f'protected persona qualification doctor could not run: {exc}')
        return
    if len(result.stdout)>65536 or len(result.stderr)>65536 or result.stderr:
        note('FAIL','protected persona qualification doctor emitted invalid or excessive output')
        return
    try:
        report=json.loads(result.stdout.decode('utf-8','strict'))
        expected_fields={
            'activation_blockers',
            'instance_slug',
            'production_activation',
            'schema_version',
            'status',
        }
        if (
            type(report) is not dict
            or set(report)!=expected_fields
            or report.get('schema_version')!='john-lomein.persona-qualification-doctor.v1'
            or report.get('instance_slug')!=slug
            or type(report.get('production_activation')) is not bool
            or type(report.get('activation_blockers')) is not list
            or any(
                not isinstance(item,str) or not item or len(item)>160
                for item in report['activation_blockers']
            )
            or len(set(report['activation_blockers']))!=len(report['activation_blockers'])
            or result.stdout!=(
                json.dumps(report,sort_keys=True,separators=(',',':')).encode('ascii')+b'\n'
            )
        ):
            raise ValueError('schema or canonical encoding mismatch')
    except Exception as exc:
        note('FAIL',f'protected persona qualification doctor report is invalid: {exc}')
        return
    status=report['status']
    blockers=report['activation_blockers']
    active=report['production_activation']
    if status=='active' and active is True and not blockers and result.returncode==0:
        note('OK','protected persona qualification route is active with no reported blockers')
    elif status=='disabled' and active is False and blockers and result.returncode==1:
        note(
            'WARN',
            'protected persona qualification is installed but disabled: '+', '.join(blockers),
        )
    else:
        note(
            'FAIL',
            f'protected persona qualification doctor state is inconsistent status={status!r} activation={active!r} exit={result.returncode}',
        )
def sha(p):
    p=Path(p); return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
def sha_text(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()
def persona_core():
    return load_persona_core(PERSONA_PATH)
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
def resolve_hermes_python(env, H):
    explicit=env.get('HERMES_PYTHON') or os.environ.get('HERMES_PYTHON')
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
def load_instance(arg):
    p=Path(arg).expanduser()
    if p.is_dir():
        primary=p/'instance.yaml'; legacy=p/'bot.yaml'
        primary_present=os.path.lexists(primary); legacy_present=os.path.lexists(legacy)
        if primary_present and legacy_present:
            raise ValueError('instance has more than one authoritative manifest candidate')
        m=primary if primary_present else legacy
    else: m=p
    return m.parent.resolve(), m.resolve(), yaml.safe_load(m.read_text(encoding='utf-8')) or {}
def public_mission_fields(mission):
    return validated_public_prompt_fields({'mission': mission})['mission']
def render_template(profile, bot, H):
    inst=bot.get('instance') or {}; mission=bot.get('mission') or {}; target=bot.get('target') or {}; runtime=bot.get('runtime') or {}; authority=bot.get('authority') or {}; gates=bot.get('gates') or {}; discord=bot.get('discord') or {}
    contract=validate_manifest_contract(bot)
    flags=contract['flags']
    posture=effective_authority_posture(bot,contract=contract)
    prompt_fields=contract['prompt']
    slug=safe_instance_slug(inst.get('slug'))
    display=public_metadata_text(inst.get('display_name'),'instance.display_name',slug,max_length=160)
    repo=safe_github_repo(target.get('repo'))
    branch=safe_default_branch(target.get('default_branch'))
    activation=posture['activation']
    forbidden=prompt_fields['gates']['forbidden_paths']
    labels=prompt_fields['gates']['readiness_labels']
    def md(items): return '\n'.join(f'- {prompt_data(x)}' for x in items) if items else '- none configured'
    mission_fields=prompt_fields['mission']
    persona_text,_,_=persona_core()
    ctx={
      'INSTANCE_SLUG': prompt_data(slug), 'INSTANCE_DISPLAY_NAME': prompt_data(display),
      'TARGET_REPO': prompt_data(repo), 'TARGET_DEFAULT_BRANCH': prompt_data(branch),
      'RUNTIME_ACTIVATION': prompt_data(activation), 'RUNTIME_MUTATION_ENABLED': prompt_data(posture['mutation_enabled']),
      'DISCORD_ENABLED': prompt_data(posture['discord_enabled']), 'DISCORD_GUIDE_GATEWAY_ENABLED': prompt_data(posture['guide_gateway_enabled']),
      'AUTHORITY_MAINTAINER_LEVEL': prompt_data(safe_authority_level(authority.get('maintainer_level'),'authority.maintainer_level','2')), 'AUTHORITY_FORGE_LEVEL': prompt_data(safe_authority_level(authority.get('forge_level'),'authority.forge_level','1')), 'AUTHORITY_GUIDE_LEVEL': prompt_data(safe_authority_level(authority.get('guide_level'),'authority.guide_level','1')), 'AUTHORITY_OVERWATCH_LEVEL': prompt_data(safe_authority_level(authority.get('overwatch_level'),'authority.overwatch_level','1.5')),
      'GATES_FORBIDDEN_PATHS_MD': md(forbidden), 'GATES_READINESS_LABELS_MD': md(labels),
      'MISSION_OWNER_AUTHORED': prompt_data(posture['mission_complete']), 'MISSION_STATEMENT': prompt_data(mission_fields['statement']),
      'MISSION_ROADMAP_SOURCES_MD': md(mission_fields['roadmap_sources']), 'MISSION_OWNER_SIGNAL_POLICY': prompt_data(mission_fields['owner_signal_policy']),
      'MISSION_PERSONALITY_VOICE': prompt_data(mission_fields['voice']), 'MISSION_PERSONALITY_CREATIVE_POSTURE': prompt_data(mission_fields['creative_posture']),
      'JOHN_LOMEIN_PERSONA_CORE': persona_text,
    }
    text=(ROOT/'profiles'/profile/'SOUL.md').read_text(encoding='utf-8')
    for k,v in ctx.items(): text=text.replace('{{'+k+'}}', str(v))
    unresolved=sorted(set(re.findall(r'\{\{[A-Z0-9_]+\}\}', text)))
    if unresolved:
        raise ValueError(f'unresolved profile placeholders: {unresolved}')
    return text
def source_pair(label, expected_text, dst):
    dst=Path(dst)
    if not dst.exists(): note('FAIL',f'{label}: missing deployed {dst}'); return
    actual=dst.read_text(encoding='utf-8', errors='ignore')
    note('OK' if actual==expected_text else 'WARN', f'{label}: source matches deployed' if actual==expected_text else f'{label}: source/deployed drift')
def gh_auth(home: Path):
    env=dict(os.environ); env.pop('GH_TOKEN',None); env.pop('GITHUB_TOKEN',None)
    env.update({'HOME':str(home),'XDG_CONFIG_HOME':str(home/'.config'),'XDG_STATE_HOME':str(home/'.local/state'),'XDG_DATA_HOME':str(home/'.local/share')})
    c,o,e=sh(['gh','auth','status','--hostname','github.com'],env=env,timeout=30)
    return c==0 and 'Logged in to github.com' in (o+e)
def parse_tools(profile,H):
    c,o,e=sh(
        ['hermes','-p',profile,'tools','list'],
        env={
            'HERMES_HOME':str(H),
            'HERMES_MANAGED_DIR':str(managed_policy_directory(H,profile)),
            'MNEMOSYNE_DATA_DIR':'',
        },
        timeout=35,
    )
    enabled=set(); disabled=set()
    if c!=0:
        note('WARN',f'{profile} tools list failed: {e or o}'); return enabled,disabled
    for line in o.splitlines():
        m=re.search(r'(enabled|disabled)\s+([a-zA-Z0-9_]+)\s+', line)
        if m:
            (enabled if m.group(1)=='enabled' else disabled).add(m.group(2))
    return enabled,disabled
def load_exact_profile_config(cfg_path):
    """Load the deployed regular file, never a redirected config surface."""
    cfg_path=Path(cfg_path)
    if cfg_path.is_symlink():
        raise ValueError('config.yaml must not be a symlink')
    try:
        cfg_stat=cfg_path.lstat()
    except FileNotFoundError as exc:
        raise ValueError('config.yaml is missing') from exc
    if not stat.S_ISREG(cfg_stat.st_mode):
        raise ValueError('config.yaml must be a regular file')
    if cfg_stat.st_uid != os.geteuid():
        raise ValueError('config.yaml must be owned by the runtime uid')
    if cfg_stat.st_nlink != 1:
        raise ValueError('config.yaml must have exactly one link')
    if cfg_stat.st_mode & 0o022:
        raise ValueError('config.yaml must not be group/other writable')
    try:
        cfg=yaml.safe_load(cfg_path.read_text(encoding='utf-8'))
    except (OSError,UnicodeError,yaml.YAMLError) as exc:
        raise ValueError(f'config.yaml is unreadable or invalid: {exc}') from exc
    if not isinstance(cfg,dict):
        raise ValueError('config.yaml root must be a mapping')
    return cfg
def load_exact_managed_policy(managed_dir):
    """Load the exact profile policy that must win over profile/default YAML."""
    managed_dir=Path(managed_dir)
    managed_root=managed_dir.parent
    if managed_root.is_symlink():
        raise ValueError('managed-policy root must not be a symlink')
    try:
        root_stat=managed_root.lstat()
    except FileNotFoundError as exc:
        raise ValueError('managed-policy root is missing') from exc
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or root_stat.st_uid != os.geteuid()
        or root_stat.st_mode & 0o022
    ):
        raise ValueError('managed-policy root metadata is unsafe')
    if managed_dir.is_symlink():
        raise ValueError('managed-policy directory must not be a symlink')
    try:
        dir_stat=managed_dir.lstat()
    except FileNotFoundError as exc:
        raise ValueError('managed-policy directory is missing') from exc
    if not stat.S_ISDIR(dir_stat.st_mode):
        raise ValueError('managed-policy path must be a directory')
    if dir_stat.st_uid != os.geteuid():
        raise ValueError('managed-policy directory must be owned by the runtime uid')
    if dir_stat.st_mode & 0o022:
        raise ValueError('managed-policy directory must not be group/other writable')
    return load_exact_profile_config(managed_dir/'config.yaml')
def load_effective_profile_config(profile,H,managed_dir,runtime_python=None):
    """Resolve only the security-relevant effective Hermes configuration.

    This executes Hermes with the exact profile and explicit managed scope.
    Failure, non-JSON output, or a missing key is ambiguity and therefore a
    Doctor failure; silently falling back to raw YAML would miss the layer that
    Hermes actually applies after profile config.
    """
    runtime_python=runtime_python or resolve_hermes_python({},Path(H))
    command_prefix=[
        runtime_python,
        '-m',
        'hermes_cli.main',
        '--profile',
        profile,
        'config',
        'get',
    ]
    process_env=dict(os.environ)
    process_env.pop('MNEMOSYNE_DATA_DIR',None)
    process_env.update({
        'HERMES_HOME':str(H),
        'HERMES_MANAGED_DIR':str(managed_dir),
        'JOHN_LOMEIN_INSTANCE_HERMES_HOME':str(H),
        'JOHN_LOMEIN_HERMES_HOME':str(H),
    })
    values={}
    for key in (
        'memory',
        'agent.disabled_toolsets',
        'plugins',
        'mcp_servers',
        'platform_toolsets',
    ):
        try:
            proc=subprocess.run(
                [*command_prefix,key,'--json'],
                capture_output=True,
                text=True,
                timeout=35,
                env=process_env,
            )
        except Exception as exc:
            raise ValueError(f'effective Hermes config probe failed for {key}: {exc}') from exc
        if proc.returncode != 0:
            detail=(proc.stderr or proc.stdout or '').strip()
            raise ValueError(
                f'effective Hermes config probe failed for {key}: {detail or proc.returncode}'
            )
        try:
            values[key]=json.loads(proc.stdout)
        except (TypeError,json.JSONDecodeError) as exc:
            raise ValueError(
                f'effective Hermes config probe returned non-JSON for {key}'
            ) from exc
    return {
        'memory':values['memory'],
        'agent':{'disabled_toolsets':values['agent.disabled_toolsets']},
        'plugins':values['plugins'],
        'mcp_servers':values['mcp_servers'],
        'platform_toolsets':values['platform_toolsets'],
    }
def check_profile_memory_boundary(role,profile,cfg,pdir):
    """Fail Doctor when built-in/model-facing memory controls drift."""
    errors=agent_memory_boundary_errors(cfg,role)
    if errors:
        for error in errors:
            note('FAIL',f'{profile} agent-memory boundary: {error}')
    else:
        note(
            'OK',
            f'{profile} local Honcho active; built-in and model-facing memory controls disabled',
        )
    provider_asset=pdir/'plugins'/MNEMOSYNE_PLUGIN
    provider_asset_absent=not (
        provider_asset.exists() or provider_asset.is_symlink()
    )
    note(
        'OK' if provider_asset_absent else 'FAIL',
        f'{profile} has no profile-local Mnemosyne agent plugin'
        if provider_asset_absent
        else f'{profile} exposes a profile-local Mnemosyne agent plugin',
    )
    return not errors and provider_asset_absent
def check_effective_profile_memory_boundary(role,profile,cfg):
    errors=agent_memory_boundary_errors(cfg,role,effective=True)
    if errors:
        for error in errors:
            note('FAIL',f'{profile} effective agent-memory boundary: {error}')
    else:
        note(
            'OK',
            f'{profile} effective config pins Honcho while model-facing memory/plugin/MCP tools stay disabled',
        )
    return not errors
def check_model_memory_toolsets(profile,disabled):
    required=set(DISABLED_AGENT_MEMORY_TOOLSETS)
    missing=sorted(required-set(disabled))
    note(
        'OK' if not missing else 'FAIL',
        f'{profile} model-facing memory/session toolsets disabled'
        if not missing
        else f'{profile} model-facing memory/session toolsets exposed or unproven: {missing}',
    )
    return not missing
def local_skill_names(pdir):
    root=pdir/'skills/software-development'; names=[]
    if root.exists():
        for s in root.rglob('SKILL.md'):
            names.append(s.parent.name)
    return sorted(names)
def omh_skill_names(pdir):
    root=pdir/'skills/omh'; names=[]
    if root.exists():
        for s in root.rglob('SKILL.md'):
            names.append(s.parent.name)
    return sorted(names)
def omh_enabled(bot):
    return manifest_boolean_flags(bot)['omh_enabled']
def omh_required(bot):
    return manifest_boolean_flags(bot)['omh_required']
def omh_home(bot, H):
    wf=bot.get('workflows') or {}
    return Path(os.path.expanduser(str(wf.get('omh_home') or (H/'omh')))).resolve()
def omh_source(bot,H):
    return (omh_home(bot,H)/'skills').resolve()
def implementation_mode(bot):
    return str((bot.get('workflows') or {}).get('implementation_mode') or 'hermes_direct')
def implementation_executor(bot):
    return str((bot.get('workflows') or {}).get('implementation_executor') or 'codex')
def expected_omh_skills(bot, role):
    if not omh_enabled(bot): return []
    raw=validated_omh_skills_by_role(bot).get(role)
    if isinstance(raw, list): return sorted(str(x) for x in raw)
    return sorted(DEFAULT_OMH_SKILLS.get(role, []))
def omh_level(bot):
    return 'FAIL' if omh_required(bot) else 'WARN'
def launch_loaded(label: str) -> bool:
    c,o,e=sh(['launchctl','print',f'gui/{os.getuid()}/{label}'],timeout=12)
    return c==0
def launchagent_environment(label: str) -> dict:
    path=Path.home()/'Library'/'LaunchAgents'/f'{label}.plist'
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'LaunchAgent plist missing or redirected: {path}')
    try:
        obj=plistlib.loads(path.read_bytes())
    except Exception as exc:
        raise ValueError(f'LaunchAgent plist unreadable: {path}: {exc}') from exc
    values=obj.get('EnvironmentVariables')
    if not isinstance(values,dict):
        raise ValueError(f'LaunchAgent environment missing: {path}')
    return values
def check_launchagent_model_environment(label,profile,H,*,require_isolation=False):
    try:
        values=launchagent_environment(label)
    except ValueError as exc:
        note('FAIL',str(exc))
        return False
    expected=str(managed_policy_directory(H,profile))
    checks={
        'managed_policy': values.get('HERMES_MANAGED_DIR')==expected,
        'mnemosyne_absent': 'MNEMOSYNE_DATA_DIR' not in values,
        'kanban_dispatch_disabled': values.get(
            'HERMES_KANBAN_DISPATCH_IN_GATEWAY'
        )=='0',
    }
    if require_isolation:
        plist_path=Path.home()/'Library'/'LaunchAgents'/f'{label}.plist'
        try:
            plist=plistlib.loads(plist_path.read_bytes())
        except Exception:
            plist={}
        args=plist.get('ProgramArguments') or []
        real_home=Path.home()
        expected_gateway_locks=gateway_lock_root(real_home)
        try:
            lock_ok=(
                validate_gateway_lock_root(real_home)==expected_gateway_locks
            )
        except GatewayLockContractError:
            lock_ok=False
        checks.update({
            'isolation_required': values.get('BOT_MODEL_MEMORY_ISOLATION')=='required',
            'private_root': values.get('BOT_STEWARD_PRIVATE_ROOT')==str(H/'private'/'learning-steward'),
            'projection_root': values.get('BOT_STEWARD_PROJECTION_ROOT')==str(H/'state'/'learning'),
            'real_home': values.get('HERMES_REAL_HOME')==str(real_home),
            'gateway_lock_path': values.get('HERMES_GATEWAY_LOCK_DIR')==str(expected_gateway_locks),
            'gateway_lock_contract': lock_ok,
            'isolation_entrypoint': str(H/'scripts'/'john_lomein_model_isolation.py') in args,
            'isolated_python': '-I' in args,
            'profile_scope': args.count(profile)==2,
        })
    failed=[name for name,passed in checks.items() if not passed]
    ok=not failed
    note(
        'OK' if ok else 'FAIL',
        f'{label} pins profile managed policy without Mnemosyne model env '
        'and disables unused Hermes Kanban dispatch'
        + (' and enters the OS model sandbox' if require_isolation else '')
        if ok
        else f'{label} model environment contract failed checks={failed}',
    )
    return ok
def check_omh_bridge(bot, H, env, catalog_sources):
    oh=omh_home(bot,H)
    if not omh_enabled(bot):
        cfg_path=H/'config.yaml'
        cfg=yaml.safe_load(cfg_path.read_text(encoding='utf-8')) if cfg_path.exists() else {}
        cfg=cfg or {}
        plugins=cfg.get('plugins') or {}
        enabled_plugins=plugins.get('enabled') or []
        plugin_entries=plugins.get('entries') or {}
        mcp_servers=cfg.get('mcp_servers') or {}
        external_dirs=(cfg.get('skills') or {}).get('external_dirs') or []
        def points_to_omh(value):
            raw=Path(os.path.expanduser(str(value)))
            candidate=(raw if raw.is_absolute() else H/raw).resolve()
            return candidate == oh or oh in candidate.parents
        platform_toolsets=cfg.get('platform_toolsets')
        platform_values=platform_toolsets.values() if isinstance(platform_toolsets,dict) else ()
        stale_toolset=any('omh' in values for values in platform_values if isinstance(values,list))
        stale=(
            oh.exists()
            or (H/'plugins'/'omh').exists()
            or 'omh' in enabled_plugins
            or 'omh' in plugin_entries
            or 'omh' in mcp_servers
            or any(points_to_omh(value) for value in external_dirs)
            or stale_toolset
        )
        note('FAIL' if stale else 'OK', 'legacy OMH disabled but active artifacts remain' if stale else 'legacy OMH disabled and active artifacts removed')
        return
    level=omh_level(bot)
    bridge_report=H/'state/john-lomein-omh-bridge.json'
    note('OK' if bridge_report.exists() else level, f'OMH bridge setup report present: {bridge_report}' if bridge_report.exists() else f'OMH bridge setup report missing: {bridge_report}')
    if bridge_report.exists():
        try:
            data=json.loads(bridge_report.read_text(encoding='utf-8'))
            note('OK' if data.get('status')=='configured' else level, f"OMH bridge setup status={data.get('status')}")
        except Exception as exc:
            note(level, f'OMH bridge setup report unreadable: {exc}')
    manifest=oh/'manifest.json'
    note('OK' if manifest.exists() else level, f'OMH managed manifest present: {manifest}' if manifest.exists() else f'OMH managed manifest missing: {manifest}')
    routing_component=catalog_sources.get('oh-my-hermes')
    skill_dir=(oh/'skills'/routing_component/'SKILL.md') if routing_component else None
    skill_installed=skill_dir is not None and skill_dir.exists()
    note('OK' if skill_installed else level, f'OMH managed skills installed under runtime OMH home' if skill_installed else f'OMH managed skills missing under runtime OMH home: {oh/"skills"}')
    plugin_dir=H/'plugins/omh'
    plugin_manifest=plugin_dir/'.omh-plugin-manifest.json'
    plugin_yaml=plugin_dir/'plugin.yaml'
    note('OK' if plugin_manifest.exists() and plugin_yaml.exists() else level, f'OMH Hermes plugin bundle present: {plugin_dir}' if plugin_manifest.exists() and plugin_yaml.exists() else f'OMH Hermes plugin bundle missing/incomplete: {plugin_dir}')
    cfg_path=H/'config.yaml'
    cfg=yaml.safe_load(cfg_path.read_text(encoding='utf-8')) if cfg_path.exists() else {}
    cfg=cfg or {}
    external_dirs=[str(x) for x in ((cfg.get('skills') or {}).get('external_dirs') or [])]
    note('OK' if str(oh/'skills') in external_dirs else level, f'OMH managed skills registered in runtime config' if str(oh/'skills') in external_dirs else f'OMH managed skills not registered in runtime config: {external_dirs}')
    mcp_servers=cfg.get('mcp_servers') or {}
    note('OK' if 'omh' in mcp_servers else level, 'OMH MCP bridge registered in runtime config' if 'omh' in mcp_servers else 'OMH MCP bridge missing from runtime config')
    root_env=dict(env)
    root_env.pop('HERMES_MANAGED_DIR',None)
    c,o,e=sh(['hermes','plugins','list','--json'],env=root_env,timeout=45)
    if c==0:
        try:
            plugins=json.loads(o or '[]')
            omh_plugin=next((p for p in plugins if p.get('name')=='omh'), None)
            note('OK' if omh_plugin and omh_plugin.get('status')=='enabled' else level, f'OMH Hermes plugin enabled' if omh_plugin and omh_plugin.get('status')=='enabled' else f'OMH Hermes plugin not enabled: {omh_plugin}')
        except Exception as exc:
            note(level, f'OMH plugin list unreadable: {exc}')
    else:
        note(level, f'OMH plugin list failed: {e or o}')
    c,o,e=sh(['hermes','mcp','list'],env=root_env,timeout=45)
    if c==0:
        note('OK' if re.search(r'(?m)^\s*omh\s', o or '') and 'enabled' in o.lower() else level, 'OMH MCP bridge visible and enabled to Hermes' if re.search(r'(?m)^\s*omh\s', o or '') and 'enabled' in o.lower() else f'OMH MCP bridge not visible/enabled: {o[:220]}')
    else:
        note(level, f'OMH MCP list failed: {e or o}')
    if shutil.which('omh'):
        c,o,e=sh(['omh','--omh-home',str(oh),'--hermes-home',str(H),'doctor','--json'],env=env,timeout=60)
        if c==0:
            note('OK','omh doctor passed for isolated runtime')
        else:
            note(level, f'omh doctor failed for isolated runtime: {(e or o)[:260]}')
    else:
        note(level, 'omh command missing; cannot run isolated runtime omh doctor')
def main():
    if len(sys.argv)!=2:
        print('usage: doctor-instance.py /path/to/instance', file=sys.stderr); return 2
    try:
        idir, manifest, bot=load_instance(sys.argv[1])
    except (OSError, ValueError, yaml.YAMLError):
        print('john-lomein product instance doctor')
        note('FAIL','instance manifest selection or content is invalid')
        return 2
    inst=bot.get('instance') or {}; mission=bot.get('mission') or {}; target=bot.get('target') or {}; runtime=bot.get('runtime') or {}; profiles=bot.get('profiles') or {}; model=bot.get('model') or {}; gates=bot.get('gates') or {}; authority=bot.get('authority') or {}; learning=bot.get('learning') or {}; release=bot.get('release') or {}
    try:
        contract=validate_manifest_contract(bot)
        flags=contract['flags']
        posture=effective_authority_posture(bot,contract=contract)
        authority_projection=authority_projection_evidence(posture)
        requested_authority=authority_projection['requested']
        effective_authority=authority_projection['effective']
        autonomy_policy=contract['autonomy']
        collaboration=collaboration_policy(bot)
        slug=safe_instance_slug(inst.get('slug'))
        display=public_metadata_text(inst.get('display_name'),'instance.display_name',slug,max_length=160)
        repo=safe_github_repo(target.get('repo'))
        branch=safe_default_branch(target.get('default_branch'))
        requested_activation=safe_runtime_activation(runtime.get('activation'))
        safe_authority_level(authority.get('maintainer_level'),'authority.maintainer_level','2')
        safe_authority_level(authority.get('forge_level'),'authority.forge_level','1')
        safe_authority_level(authority.get('guide_level'),'authority.guide_level','1')
        safe_authority_level(authority.get('overwatch_level'),'authority.overwatch_level','1.5')
        npm_tag=safe_npm_tag(release.get('npm_tag'))
        publish_workflow=safe_publish_workflow(release.get('publish_workflow'))
        role_profiles=canonical_role_profiles(bot)
        discord_enabled=effective_authority['discord']
        guide_gateway_enabled=effective_authority['guide_gateway']
        local,H=validate_runtime_checkout_separation(
            Path(os.path.expanduser(str(target.get('local_checkout') or target.get('local') or f'~/.john-lomein/instances/{slug}/work/repo'))),
            Path(os.path.expanduser(str(runtime.get('hermes_home') or f'~/.john-lomein/instances/{slug}/hermes'))),
        )
    except ValueError as exc:
        print('john-lomein product instance doctor')
        note('FAIL',str(exc))
        return 2
    role_skills={'maintainer':['john-lomein-maintainer','john-lomein-communication','john-lomein-native-workflows'],'forge':['john-lomein-forge','john-lomein-communication','john-lomein-native-workflows'],'guide':['john-lomein-build-room','john-lomein-guide-playground','john-lomein-guide-proposals','john-lomein-communication','john-lomein-native-workflows'],'overwatch':['john-lomein-overwatch','john-lomein-communication','john-lomein-native-workflows'],'learning_steward':['john-lomein-learning-steward','john-lomein-communication','john-lomein-native-workflows']}
    env={
        'HERMES_HOME':str(H),
        'BOT_HERMES_HOME':str(H),
        'BOT_HERMES_MANAGED_ROOT':str(H/'managed-policy'),
        'HERMES_MANAGED_DIR':str(
            managed_policy_directory(H,role_profiles['maintainer'])
        ),
        'JOHN_LOMEIN_INSTANCE_HERMES_HOME':str(H),
        'BOT_MAINTAINER_PROFILE':role_profiles['maintainer'],
        'BOT_LOCAL':str(local),
        'BOT_MODEL_MEMORY_ISOLATION':contract['model_memory_isolation'],
        'BOT_STEWARD_PRIVATE_ROOT':str(H/'private'/'learning-steward'),
        'BOT_STEWARD_PROJECTION_ROOT':str(H/'state'/'learning'),
        'BOT_MODEL_PROVIDER':str(model.get('provider') or 'openai-codex'),
        'BOT_FALLBACK_PROVIDER':str((model.get('fallback') or {}).get('provider') or ''),
        'HERMES_REAL_HOME':str(
            Path(os.environ.get('HERMES_REAL_HOME') or Path.home())
        ),
        'JOHN_LOMEIN_AUTH_AUTHORITY_HOME':str(
            Path(os.environ.get('HERMES_REAL_HOME') or Path.home())/'.hermes'
        ),
    }
    print('john-lomein product instance doctor')
    print(f'product: {ROOT}')
    print(f'instance: {idir}')
    print(f'manifest: {manifest}')
    print(f'display: {display}')
    print(f'runtime: {H}')
    print(f'target repo: {repo}')
    print('profiles: '+', '.join(f'{k}={v}' for k,v in role_profiles.items()))
    print('health domains: product_source, deployed_runtime, persona_qualification, autonomy_control, managed_checkout_github, queue_release, protected_release, discord_visibility')
    try:
        _,persona_version,persona_sha=persona_core()
        persona_valid=True
    except (OSError,ValueError) as exc:
        persona_version=''; persona_sha=''; persona_valid=False
        note('FAIL',f'canonical persona invalid: {exc}')
    if persona_valid:
        note('OK',f'canonical persona valid version={persona_version} sha256={persona_sha[:12]}')
    try:
        mission_fields=contract['prompt']['mission']
        mission_public_safe=True
    except ValueError:
        mission_fields={}
        mission_public_safe=False
    mission_complete=bool(contract['mission_complete'])
    mission_candidate_ready=bool(contract.get('mission_candidate_complete'))
    mission_authority_requested=bool(
        requested_authority['activation']=='active'
        or requested_authority['mutation']
        or requested_authority['discord']
        or requested_authority['guide_gateway']
        or requested_authority['protected_release']
        or requested_authority['portfolio']
    )
    mission_level=mission_authority_level(
        mission_complete=mission_complete,
        mission_public_safe=mission_public_safe,
        authority_requested=mission_authority_requested,
    )
    note(mission_level, 'owner-authored public-safe mission card configured' if mission_complete else ('mission card contains an unsafe public field; deployment is blocked' if not mission_public_safe else ('active authority is blocked because the owner mission card is incomplete' if mission_authority_requested else ('mission candidate is public-safe and awaits exact owner adoption; observer roles remain gated' if mission_candidate_ready else 'mission card is incomplete; observer roles use conservative defaults'))))
    note(
        'OK',
        'authority projection '
        f"requested={json.dumps(requested_authority,sort_keys=True,separators=(',',':'))} "
        f"effective={json.dumps(effective_authority,sort_keys=True,separators=(',',':'))}",
    )
    if not mission_public_safe:
        return 1
    if mission_fields.get('personality_override_ignored'):
        note('WARN','mission personality free text differs from the product-controlled John persona preset and is ignored')
    owner_approvers=split_csv(authority.get('owner_approvers') or (bot.get('discord') or {}).get('owner_user_ids') or [])
    if requested_authority['mutation'] or requested_authority['discord']:
        note('OK' if owner_approvers else 'WARN', f'trusted owner approver registry configured count={len(owner_approvers)}' if owner_approvers else 'trusted owner approver registry empty; owner gates fail closed until authority.owner_approvers or discord.owner_user_ids is configured')
        trust_key=H/'state'/'gateway'/'trust-assertion.public.pem'
        trust_fingerprint=str(authority.get('trust_public_key_sha256') or (bot.get('discord') or {}).get('trust_public_key_sha256') or '')
        if trust_key.exists():
            mode=trust_key.lstat().st_mode & 0o777
            import hashlib
            actual=hashlib.sha256(trust_key.read_bytes()).hexdigest() if not trust_key.is_symlink() else ''
            key_ok=(not trust_key.is_symlink()) and not (mode & 0o222) and trust_fingerprint and actual==trust_fingerprint
            note('OK' if key_ok else 'WARN', 'signed trust assertion public key present with pinned fingerprint for external-gateway verification' if key_ok else f'signed trust assertion public key not safely pinned; route/approval gates fail closed mode={oct(mode)} fingerprint_configured={bool(trust_fingerprint)} fingerprint_match={bool(trust_fingerprint and actual==trust_fingerprint)} symlink={trust_key.is_symlink()}')
        else:
            note('WARN','signed trust assertion public key missing; Discord readiness routing and release approvals fail closed until the external gateway installs it')
    note('OK','runtime role/profile bindings exactly match the canonical John Lomein product map')
    note('OK' if H.exists() else 'FAIL', f'runtime exists: {H}' if H.exists() else f'runtime missing: {H}')
    note('OK' if (H/'instance.yaml').exists() else 'FAIL', 'manifest deployed into runtime' if (H/'instance.yaml').exists() else 'manifest not deployed into runtime')
    try:
        root_config_path=H/'config.yaml'
        if root_config_path.is_symlink() or not root_config_path.is_file():
            raise ValueError('runtime root config missing or unsafe')
        root_config=yaml.safe_load(root_config_path.read_text(encoding='utf-8')) or {}
        peer_registry=root_config.get('bot_peers') or {}
        if not isinstance(peer_registry,(dict,list)):
            raise ValueError('runtime bot_peers registry has an invalid shape')
        peer_count=len(peer_registry)
        peers_ok=collaboration['peer_messaging_enabled'] or peer_count==0
        note(
            'OK' if peers_ok else 'FAIL',
            f'Hermes Peer registry matches policy enabled={collaboration["peer_messaging_enabled"]} count={peer_count}'
            if peers_ok
            else f'Hermes Peer registry must be empty while peer messaging is disabled count={peer_count}',
        )
    except (OSError,ValueError,yaml.YAMLError) as exc:
        note('FAIL',f'Hermes Peer registry check failed: {exc}')
    hermes_command=shutil.which('hermes')
    if hermes_command:
        hc,ho,he=sh(
            [
                sys.executable,
                str(ROOT/'scripts'/'john-lomein-continuity-hook-canary.py'),
                '--hermes',
                hermes_command,
                '--timeout',
                '45',
            ],
            timeout=60,
        )
        try:
            hook_canary=json.loads(ho or '{}')
        except Exception:
            hook_canary={}
        hook_canary_ok=(
            hc==0
            and hook_canary.get('schema_version')
            =='john-lomein.continuity-hook-canary.v1'
            and hook_canary.get('status')=='verified'
            and hook_canary.get('context_target')=='current_user_message'
        )
        note(
            'OK' if hook_canary_ok else 'FAIL',
            'installed Hermes injects pre_llm_call context into the actual current-user model request'
            if hook_canary_ok
            else f'installed Hermes continuity hook capability canary failed: {he or ho}',
        )
        pc,po,pe=sh(
            [
                sys.executable,
                str(ROOT/'scripts'/'john-lomein-continuity-hook-canary.py'),
                '--hermes',
                hermes_command,
                '--asset-root',
                str(H),
                '--timeout',
                '45',
            ],
            timeout=60,
        )
        try:
            product_hook_canary=json.loads(po or '{}')
        except Exception:
            product_hook_canary={}
        product_hook_ok=(
            pc==0
            and product_hook_canary.get('schema_version')
            =='john-lomein.continuity-product-hook-canary.v1'
            and product_hook_canary.get('status')=='verified'
            and product_hook_canary.get('profile')
            ==role_profiles['maintainer']
            and product_hook_canary.get('context_target')
            =='current_user_message'
        )
        note(
            'OK' if product_hook_ok else 'FAIL',
            'deployed John continuity plugin/helper/store/profile path injects a nonce-backed capsule into the actual model request'
            if product_hook_ok
            else f'deployed John continuity product canary failed: {pe or po}',
        )
    else:
        note('FAIL','Hermes is unavailable; continuity hook injection cannot be proven')
    try:
        continuity_entries,continuity_head=verify_continuity_store(
            H/'state'/'continuity'
        )
        note(
            'OK',
            'continuity ledger/head verify exactly '
            f"sequence={continuity_head['sequence']} "
            f"entries={len(continuity_entries)}",
        )
    except ContinuityError as exc:
        note(
            'FAIL',
            f'continuity store failed closed: {exc.code}',
        )
    try:
        import_status=continuity_import_status(H)
        if import_status['configured']:
            import_verification=verify_continuity_import(H)
            note(
                'OK',
                'signed continuity importer verified '
                f"enabled={import_verification['enabled']} "
                f"records={import_verification['import_sequence']} "
                f"suppressed={import_verification['suppressed_entry_count']}",
            )
        else:
            dormant_ok=not import_status.get('import_state_initialized',False)
            note(
                'OK' if dormant_ok else 'FAIL',
                'signed continuity importer is safely dormant and credential-free'
                if dormant_ok
                else 'signed continuity importer configuration is missing while durable importer state remains',
            )
    except (ContinuityImporterError,ContinuityProtocolError,ContinuityError) as exc:
        note(
            'FAIL',
            f'signed continuity importer failed closed: {getattr(exc,"code","state_invalid")}',
        )
    if 'openai-codex' in {
        str(model.get('provider') or ''),
        str((model.get('fallback') or {}).get('provider') or ''),
    }:
        try:
            auth_projection=verify_auth_projection(
                H,
                profiles=[
                    H/'profiles'/profile
                    for profile in role_profiles.values()
                ],
                authority_home=Path(env['JOHN_LOMEIN_AUTH_AUTHORITY_HOME']),
            )
            note(
                'OK',
                'OpenAI Codex auth is access-only and synchronized '
                f"across targets={auth_projection['targets']}",
            )
        except AuthProjectionError as exc:
            note(
                'FAIL',
                f'OpenAI Codex access projection failed closed: {exc}',
            )
    steward_private=H/'private'/'learning-steward'
    private_memory=steward_private/'mnemosyne'/'data'
    projection_root=H/'state'/'learning'
    private_ok=(
        steward_private.is_dir()
        and not steward_private.is_symlink()
        and private_memory.is_dir()
        and projection_root.is_dir()
        and not projection_root.is_symlink()
    )
    note(
        'OK' if private_ok else 'FAIL',
        'private steward/Mnemosyne root and sanitized continuity projection exist'
        if private_ok
        else 'private steward/Mnemosyne root or sanitized continuity projection is missing/redirected',
    )
    legacy_memory=H/'mnemosyne'
    note(
        'OK' if not legacy_memory.exists() and not legacy_memory.is_symlink() else 'FAIL',
        'legacy model-readable Mnemosyne root is absent'
        if not legacy_memory.exists() and not legacy_memory.is_symlink()
        else f'legacy model-readable Mnemosyne path remains: {legacy_memory}',
    )
    if contract['model_memory_isolation']=='required' and private_ok:
        canary_ok,canary_detail=run_isolation_canary(env,python=resolve_hermes_python(env,H))
        note(
            'OK' if canary_ok else 'FAIL',
            f'model OS boundary canary passed backend={canary_detail}'
            if canary_ok
            else f'model OS boundary canary failed: {canary_detail}',
        )
    elif contract['model_memory_isolation']=='required':
        note('FAIL','model OS boundary canary could not run without safe private/projection roots')
    else:
        note('OK','model memory isolation disabled only because learning is disabled')
    mnemosyne_dependency=H/'plugins/mnemosyne'
    dependency_ok=(
        mnemosyne_dependency.is_symlink()
        and mnemosyne_dependency.exists()
        and mnemosyne_dependency.resolve().is_dir()
    )
    note(
        'OK' if dependency_ok else 'WARN',
        'Mnemosyne deterministic learning-index dependency is an exact runtime symlink'
        if dependency_ok
        else 'Mnemosyne deterministic learning-index dependency is missing or not an exact symlink',
    )
    persona_evidence=H/'state'/'john-lomein-persona.json'
    if persona_evidence.exists() and persona_valid:
        try:
            deployed_persona=json.loads(persona_evidence.read_text(encoding='utf-8'))
            evidence_ok=deployed_persona.get('persona_version')==persona_version and deployed_persona.get('sha256')==persona_sha
            note('OK' if evidence_ok else 'WARN', f'deployed persona evidence matches canonical version={persona_version}' if evidence_ok else 'deployed persona evidence is stale; redeploy to invalidate long-lived sessions')
        except Exception as exc:
            note('WARN',f'deployed persona evidence unreadable: {exc}')
    else:
        note('WARN','deployed persona evidence missing; redeploy to compose the canonical identity and restart long-lived sessions')
    qualification_script=ROOT/'scripts'/'john-lomein-persona-qualification.py'
    if qualification_script.exists():
        qc,qo,qe=sh(
            [
                sys.executable,
                str(qualification_script),
                'status',
                '--instance',
                str(manifest),
            ],
            env=env,
            timeout=30,
        )
        if qc==0:
            try:
                qualification=json.loads(qo)
                qualification_state=str(qualification.get('status') or '')
                qualification_reason=str(qualification.get('reason') or '')
                qualification_candidates=qualification.get('candidates') or []
                if qualification_state=='qualified':
                    note(
                        'WARN',
                        f'persona qualification local conformance is current for configured models count={len(qualification_candidates)} but is not operator-attested; public digests are not an authentication boundary',
                    )
                elif qualification_state=='failed':
                    note(
                        'FAIL',
                        f'persona qualification status=failed: {qualification_reason}',
                    )
                elif qualification_state in {'incomplete','missing','stale'}:
                    note(
                        'WARN',
                        f'persona qualification status={qualification_state}: {qualification_reason}',
                    )
                else:
                    note(
                        'FAIL',
                        f'persona qualification returned an invalid state: {qualification_state or "<empty>"}',
                    )
            except Exception as exc:
                note('FAIL',f'persona qualification status is unreadable: {exc}')
        else:
            note(
                'FAIL',
                f'persona qualification evidence is invalid or tampered: {qe or qo}',
            )
    else:
        note('FAIL',f'persona qualification runner missing: {qualification_script}')
    protected_qualification_doctor(slug)
    autonomy_evidence=H/'state'/'john-lomein-autonomy-policy.json'
    if autonomy_evidence.exists():
        try:
            deployed_autonomy=json.loads(autonomy_evidence.read_text(encoding='utf-8'))
            autonomy_evidence_ok=(
                deployed_autonomy.get('schema_version')=='john-lomein.autonomy-deployment.v1'
                and deployed_autonomy.get('policy')==autonomy_policy
                and deployed_autonomy.get('policy_sha256')==sha256_json(autonomy_policy)
            )
            note('OK' if autonomy_evidence_ok else 'FAIL', 'deployed autonomy policy stamp matches the validated instance contract' if autonomy_evidence_ok else 'deployed autonomy policy stamp is stale or invalid; redeploy before mutation')
        except Exception as exc:
            note('FAIL',f'deployed autonomy policy stamp unreadable: {exc}')
    else:
        note('FAIL','deployed autonomy policy stamp missing; redeploy before mutation')
    if H.exists():
        try:
            autonomy_state=autonomy_status(H,autonomy_policy)
            autonomy_alerts=[]
            for lane,lane_state in autonomy_state['lanes'].items():
                circuit=lane_state['circuit']; daily=lane_state['daily']
                if circuit['open']:
                    autonomy_alerts.append(f"{lane}:circuit_open_until={circuit['open_until']}")
                if daily['lane_runs']>=daily['lane_run_limit']:
                    autonomy_alerts.append(f"{lane}:daily_runs={daily['lane_runs']}/{daily['lane_run_limit']}")
            first_daily=autonomy_state['lanes']['maintainer']['daily']
            if first_daily['runtime_seconds']>=first_daily['runtime_limit_seconds']:
                autonomy_alerts.append(f"runtime={first_daily['runtime_seconds']}/{first_daily['runtime_limit_seconds']}")
            for effect,used in first_daily['effect_counts'].items():
                limit=first_daily['effect_limits'][effect]
                if used>=limit and limit>0:
                    autonomy_alerts.append(f"{effect}={used}/{limit}")
            note('OK' if not autonomy_alerts else 'WARN', f"autonomy journal valid events={autonomy_state['event_count']} active_runs={len(autonomy_state['active_runs'])} pending_effects={autonomy_state['pending_effects']}" if not autonomy_alerts else f"autonomy control alerts: {autonomy_alerts}")
        except (AutonomyError,ValueError) as exc:
            note('FAIL',f'autonomy journal/control invalid: {exc}')
    c,o,e=sh(['gh','repo','view',repo,'--json','nameWithOwner,visibility,defaultBranchRef,pushedAt,url'],env=env,timeout=30)
    if c==0:
        data=json.loads(o); note('OK',f"GitHub reachable: {data['nameWithOwner']} default={data['defaultBranchRef']['name']} visibility={data['visibility']}")
    else: note('FAIL',f'gh repo view failed: {e or o}')
    if local.exists():
        sh(['git','fetch','--prune','origin'],cwd=local,env=env,timeout=60)
        c,o,e=sh(['git','status','--short','--branch'],cwd=local,env=env,timeout=25)
        first=o.splitlines()[0] if o else ''
        dirty=[x for x in o.splitlines()[1:] if x.strip()]
        note('OK' if first.startswith(f'## {branch}') else 'WARN', f'managed checkout on {branch}' if first.startswith(f'## {branch}') else f'managed checkout branch status: {first}')
        note('OK' if not dirty else 'WARN', 'managed checkout clean' if not dirty else f'managed checkout dirty items={len(dirty)} {DIRTY_CHECKOUT_RECOVERY}')
        c2,o2,e2=sh(['git','rev-list','--left-right','--count',f'HEAD...origin/{branch}'],cwd=local,env=env,timeout=25)
        if c2==0:
            parts=o2.split(); ahead=parts[0] if parts else '?'; behind=parts[1] if len(parts)>1 else '?'
            note('OK' if ahead=='0' and behind=='0' else 'WARN', f'managed checkout freshness ahead={ahead} behind={behind}')
    else:
        note('FAIL',f'managed checkout missing: {local}')
    required_enabled_private={'web','terminal','file','skills','todo'}
    required_enabled_guide={'web','skills','todo'}
    high_risk={'browser','code_execution','vision','video','image_gen','video_gen','x_search','moa','tts','clarify','delegation','cronjob','homeassistant','spotify','yuanbao','computer_use'}
    omh_catalog={}
    if omh_enabled(bot):
        try:
            omh_catalog=omh_catalog_skill_sources(omh_home(bot,H))
        except ValueError as exc:
            note('FAIL' if omh_required(bot) else 'WARN', f'instance-local OMH skill catalog invalid: {exc}')
    for role,profile in role_profiles.items():
        pdir=H/'profiles'/profile
        note('OK' if pdir.exists() else 'FAIL', f'profile exists: {profile} ({role})')
        if pdir.exists():
            source_pair(f'{role} SOUL', render_template(profile,bot,H), pdir/'SOUL.md')
            actual=local_skill_names(pdir); exp=sorted(role_skills[role])
            note('OK' if actual==exp else 'FAIL', f'{profile} profile-local skills exactly match: {actual}' if actual==exp else f'{profile} skills mismatch expected={exp} actual={actual}')
            for skill in exp:
                if (pdir/f'skills/software-development/{skill}/SKILL.md').exists() and sha(ROOT/f'skills/{skill}/SKILL.md')==sha(pdir/f'skills/software-development/{skill}/SKILL.md'):
                    note('OK',f'{profile} skill {skill} source matches deployed')
                else:
                    note('FAIL',f'{profile} skill {skill} missing or drifted')
            exp_omh=expected_omh_skills(bot, role); actual_omh=omh_skill_names(pdir)
            if omh_enabled(bot):
                level='FAIL' if omh_required(bot) else 'WARN'
                note('OK' if actual_omh==exp_omh else level, f'{profile} OMH skills installed: {actual_omh}' if actual_omh==exp_omh else f'{profile} OMH skills mismatch expected={exp_omh} actual={actual_omh}')
                src_root=omh_source(bot,H)
                for skill in actual_omh:
                    source_component=omh_catalog.get(skill)
                    src=(src_root/source_component/'SKILL.md') if source_component else None
                    dst=pdir/'skills/omh'/skill/'SKILL.md'
                    if src is not None and src.exists():
                        expected=normalize_skill_frontmatter_text(src.read_text(encoding='utf-8'))
                        actual=dst.read_text(encoding='utf-8') if dst.exists() else ''
                        note('OK' if sha_text(expected)==sha_text(actual) else 'WARN', f'{profile} OMH skill {skill} normalized source matches deployed' if sha_text(expected)==sha_text(actual) else f'{profile} OMH skill normalized source/deployed drift')
                    else:
                        note(level, f'{profile} OMH skill source missing: {skill} at {src_root}')
            else:
                note('OK' if not actual_omh else 'WARN', f'{profile} OMH workflows disabled' if not actual_omh else f'{profile} OMH workflows disabled but copied skills remain: {actual_omh}')
            cfg_path=pdir/'config.yaml'
            try:
                cfg=load_exact_profile_config(cfg_path)
            except ValueError as exc:
                note('FAIL',f'{profile} exact deployed config invalid: {exc}')
                cfg={}
            term=cfg.get('terminal') or {}
            bot_mode_protocol=(cfg.get('agent') or {}).get('bot_mode_protocol')
            expected_bot_mode=collaboration['bot_chat_protocol_enabled']
            note(
                'OK' if bot_mode_protocol is expected_bot_mode else 'FAIL',
                f'{profile} Bot Mode collaboration protocol matches policy: {expected_bot_mode}'
                if bot_mode_protocol is expected_bot_mode
                else f'{profile} Bot Mode collaboration protocol drift expected={expected_bot_mode} actual={bot_mode_protocol}',
            )
            check_profile_memory_boundary(role,profile,cfg,pdir)
            honcho_path=pdir/'honcho.json'
            try:
                if honcho_path.is_symlink() or not honcho_path.is_file():
                    raise ValueError('honcho config missing or unsafe')
                honcho_stat=honcho_path.stat()
                if (
                    honcho_stat.st_uid != os.geteuid()
                    or honcho_stat.st_nlink != 1
                    or not stat.S_ISREG(honcho_stat.st_mode)
                    or honcho_stat.st_mode & 0o077
                ):
                    raise ValueError('honcho config permissions are unsafe')
                honcho_data=json.loads(honcho_path.read_text(encoding='utf-8'))
                honcho_errors=profile_honcho_errors(
                    honcho_data,
                    instance_slug=slug,
                    role=role,
                    profile=profile,
                    manifest=bot,
                )
                if honcho_errors:
                    raise ValueError('; '.join(honcho_errors))
                note('OK',f'{profile} local Honcho contract is exact')
                settings=honcho_settings(bot,instance_slug=slug)
                probe_honcho_health(settings['base_url'],timeout=min(5.0,float(settings['timeout'])))
                note('OK',f'{profile} local Honcho provider is reachable')
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
                note('FAIL',f'{profile} local Honcho contract invalid: {exc}')
            managed_dir=managed_policy_directory(H,profile)
            try:
                managed_policy=load_exact_managed_policy(managed_dir)
                managed_errors=agent_memory_managed_policy_errors(
                    managed_policy,
                    role,
                )
                if managed_errors:
                    for error in managed_errors:
                        note(
                            'FAIL',
                            f'{profile} managed agent-memory policy: {error}',
                        )
                else:
                    note(
                        'OK',
                        f'{profile} exact Hermes managed policy is present',
                    )
                effective_cfg=load_effective_profile_config(
                    profile,
                    H,
                    managed_dir,
                )
                check_effective_profile_memory_boundary(
                    role,
                    profile,
                    effective_cfg,
                )
            except ValueError as exc:
                note(
                    'FAIL',
                    f'{profile} effective Hermes config is ambiguous: {exc}',
                )
            skills_cfg=cfg.get('skills') or {}
            note('OK' if skills_cfg.get('write_approval') is True and skills_cfg.get('guard_agent_created') is True else 'FAIL', f'{profile} skill writes require approval and agent-created skills are guarded' if skills_cfg.get('write_approval') is True and skills_cfg.get('guard_agent_created') is True else f'{profile} skill write gates are incomplete')
            plugins_cfg=cfg.get('plugins') or {}
            enabled_plugins=set(plugins_cfg.get('enabled') or []) if isinstance(plugins_cfg,dict) else set()
            disabled_plugins=set(plugins_cfg.get('disabled') or []) if isinstance(plugins_cfg,dict) else set()
            continuity_plugin='john-lomein-continuity'
            continuity_scope_ok=(
                continuity_plugin in enabled_plugins
                and continuity_plugin not in disabled_plugins
            )
            note(
                'OK' if continuity_scope_ok else 'FAIL',
                f'{profile} product continuity hook is enabled'
                if continuity_scope_ok
                else f'{profile} product continuity hook is missing, disabled, or stale',
            )
            continuity_plugin_path=pdir/'plugins'/continuity_plugin
            continuity_asset_ok=(
                continuity_plugin_path.is_symlink()
                and continuity_plugin_path.resolve()
                == (H/'plugins'/continuity_plugin).resolve()
            )
            note(
                'OK' if continuity_asset_ok else 'FAIL',
                f'{profile} continuity plugin asset binding is exact'
                if continuity_asset_ok
                else f'{profile} continuity plugin asset binding is unsafe or stale',
            )
            approval_plugin='john-lomein-release-approval'
            plugin_scope_ok=(
                approval_plugin in enabled_plugins
                and approval_plugin not in disabled_plugins
            ) if role=='guide' else (
                approval_plugin not in enabled_plugins
                and approval_plugin in disabled_plugins
            )
            note(
                'OK' if plugin_scope_ok else 'FAIL',
                f'{profile} protected-release approval hook scope is correct'
                if plugin_scope_ok
                else f'{profile} protected-release approval hook scope is unsafe or stale',
            )
            approval_plugin_path=pdir/'plugins'/approval_plugin
            if role=='guide':
                plugin_asset_ok=(
                    approval_plugin_path.is_symlink()
                    and approval_plugin_path.resolve()
                    == (H/'plugins'/approval_plugin).resolve()
                )
            else:
                plugin_asset_ok=not (
                    approval_plugin_path.exists()
                    or approval_plugin_path.is_symlink()
                )
            note(
                'OK' if plugin_asset_ok else 'FAIL',
                f'{profile} protected-release approval plugin asset scope is correct'
                if plugin_asset_ok
                else f'{profile} protected-release approval plugin asset scope is unsafe or stale',
            )
            note('OK' if term.get('home_mode')=='profile' else 'FAIL', f'{profile} terminal HOME isolated to profile')
            note('OK' if Path(term.get('cwd','')).expanduser()==local else 'WARN', f'{profile} workdir points at managed checkout' if Path(term.get('cwd','')).expanduser()==local else f'{profile} workdir={term.get("cwd")}')
            note('OK' if not (term.get('dangerous_command_permanent_allowlist') or []) else 'WARN', f'{profile} dangerous-command permanent allowlist empty')
            enabled,disabled=parse_tools(profile,H)
            req=required_enabled_guide if role=='guide' else required_enabled_private
            note('OK' if req <= enabled else 'FAIL', f'{profile} required toolsets enabled' if req <= enabled else f'{profile} missing enabled toolsets: {sorted(req-enabled)}')
            check_model_memory_toolsets(profile,disabled)
            known_toolsets = enabled | disabled
            # Hermes installations evolve: older product rails included toolsets
            # such as `moa` that may no longer be exposed by `hermes tools list`.
            # Do not fail closed on a toolset the runtime cannot enumerate or
            # disable; enforce only high-risk/nonessential toolsets that are
            # actually known to this Hermes build, plus role-specific known rails.
            role_nonessential = {'terminal','file','context_engine'} if role=='guide' else {'context_engine'}
            dis=(set(high_risk)|role_nonessential) & known_toolsets
            note('OK' if dis <= disabled else 'FAIL', f'{profile} high-risk/nonessential toolsets disabled' if dis <= disabled else f'{profile} high-risk/nonessential toolsets still enabled: {sorted(dis-disabled)}')
            profile_has_gh_auth=gh_auth(pdir/'home')
            if role=='guide':
                note(
                    'FAIL' if profile_has_gh_auth else 'OK',
                    f'{profile} public Guide must not have profile-local GitHub credentials'
                    if profile_has_gh_auth
                    else f'{profile} public Guide has no GitHub credentials',
                )
            else:
                note('OK' if profile_has_gh_auth else 'WARN', f'{profile} profile-local gh auth works' if profile_has_gh_auth else f'{profile} profile-local gh auth missing')
    c,o,e=sh(['hermes','-p',role_profiles['maintainer'],'cron','list','--all'],env=env,timeout=40)
    if c==0:
        core_crons=[f'john-lomein-{slug}-watchdog',f'john-lomein-{slug}-maintainer',f'john-lomein-{slug}-forge-cycle',f'john-lomein-{slug}-overwatch']
        honcho_name=f'john-lomein-{slug}-honcho-watchdog'
        learning_name=f'john-lomein-{slug}-learning-steward'
        portfolio_name=f'john-lomein-{slug}-osc-portfolio'
        cron_names=[*core_crons,honcho_name,learning_name,portfolio_name]
        expected_crons=set(core_crons) if effective_authority['mutation'] else set()
        if effective_authority['mutation'] and flags['learning_enabled']:
            expected_crons.add(learning_name)
        if effective_authority['mutation'] and effective_authority['portfolio']:
            expected_crons.add(portfolio_name)
        if honcho_settings(bot,instance_slug=slug)['watchdog_enabled'] and effective_authority['guide_required']:
            expected_crons.add(honcho_name)
        for name in cron_names:
            expected=name in expected_crons
            present=name in o
            note('OK' if present==expected else 'FAIL', f'cron state correct in instance runtime: {name} expected={expected} present={present}' if present==expected else f'cron state mismatch in instance runtime: {name} expected={expected} present={present}')
    else: note('FAIL',f'instance cron list failed: {e or o}')
    runtime_scripts=['john_lomein_auth_projection.py','john_lomein_autonomy.py','john_lomein_collaboration_contract.py','john_lomein_comment_templates.py','john_lomein_container_verifier.py','john_lomein_continuity.py','john_lomein_continuity_importer.py','john_lomein_continuity_protocol.py','john_lomein_factory_receipts.py','john_lomein_gateway_lock_contract.py','john_lomein_guide_lifecycle.py','john_lomein_owner_override.py','john_lomein_proposal.py','john_lomein_review_quorum.py','john_lomein_manifest_contract.py','john_lomein_honcho_contract.py','john_lomein_honcho_pilot.py','honcho-embedding-recovery-candidates.sql','honcho-participant-candidates.sql','honcho-participant-delete.sql','john_lomein_memory_boundary_migration.py','john_lomein_memory_contract.py','john_lomein_model_isolation.py','john_lomein_owner_actions.py','john_lomein_plugin_contract.py','john_lomein_profile_contract.py','john_lomein_protected_actions.py','john_lomein_public_safety.py','john_lomein_release_packets.py','john_lomein_scoped_publication.py','john_lomein_service_registry.py','john-lomein-continuity-hook-canary.py','john-lomein-factory-simulate.py','john-lomein-trust-assertion.py','john-lomein-auth-env.sh','john-lomein-diagnostic-tick.sh','john-lomein-watchdog.sh','john-lomein-honcho-watchdog.py','john-lomein-honcho-watchdog.sh','john-lomein-maintainer-trigger.sh','john-lomein-maintainer-prompt.txt','john-lomein-worker.py','john-lomein-gh-guard.py','john-lomein-git-guard.py','john-lomein-protected-submit.py','john-lomein-issue-intake.py','john-lomein-issue-triage.py','john-lomein-osc-portfolio-steward.py','john-lomein-osc-portfolio-trigger.sh','john-lomein-release-approve.py','john-lomein-release-bundler.py','john-lomein-release-executor.py','john-lomein-release-submit.py','john-lomein-forge-trigger.sh','john-lomein-exact-head-review.py','john-lomein-forge-orchestrator.py','john-lomein-omh-implementation.py','john-lomein-queue-health.py','john-lomein-cross-instance-learning-digest.py','john-lomein-learning-steward.py','john-lomein-learning-trigger.sh','john-lomein-overwatch-trigger.sh','john-lomein-overwatch-scan.py','john-lomein-overwatch-post.sh','john-lomein-overwatch-prompt.txt','john-lomein-keepawake.sh','install-runtime-supervisor.sh','uninstall-runtime-supervisor.sh','repair-profile-gh-auth.py','stage_profile_distribution.py','read-instance-env.py','apply-guide-discord-config.py','install-guide-gateway.sh']
    if not omh_enabled(bot):
        runtime_scripts=[name for name in runtime_scripts if name != 'john-lomein-omh-implementation.py']
    for script in runtime_scripts:
        src=ROOT/'scripts'/script; dst=H/'scripts'/script
        if src.exists():
            source_pair(f'script {script}', src.read_text(encoding='utf-8'), dst)
        else:
            note('FAIL',f'source script missing: {script}')
    for module in ['__init__.py','john_lomein_release_broker_protocol.py','john_lomein_release_broker_receipts.py']:
        src=ROOT/'release_broker'/module
        dst=H/'scripts'/'release_broker'/module
        if src.exists():
            source_pair(f'release client module {module}', src.read_text(encoding='utf-8'), dst)
        else:
            note('FAIL',f'source release client module missing: {module}')
    for plugin_asset in ['__init__.py','plugin.yaml']:
        src=ROOT/'runtime_plugins'/'john-lomein-release-approval'/plugin_asset
        dst=H/'plugins'/'john-lomein-release-approval'/plugin_asset
        if src.exists():
            source_pair(
                f'protected release approval plugin {plugin_asset}',
                src.read_text(encoding='utf-8'),
                dst,
            )
        else:
            note('FAIL',f'source protected release approval plugin asset missing: {plugin_asset}')
    for plugin_asset in ['__init__.py','plugin.yaml']:
        src=ROOT/'runtime_plugins'/'john-lomein-continuity'/plugin_asset
        dst=H/'plugins'/'john-lomein-continuity'/plugin_asset
        if src.exists():
            source_pair(
                f'continuity plugin {plugin_asset}',
                src.read_text(encoding='utf-8'),
                dst,
            )
        else:
            note('FAIL',f'source continuity plugin asset missing: {plugin_asset}')
    for plugin_asset in ['__init__.py','plugin.yaml']:
        src=ROOT/'runtime_plugins'/'john-lomein-guide-lifecycle'/plugin_asset
        dst=H/'plugins'/'john-lomein-guide-lifecycle'/plugin_asset
        if src.exists():
            source_pair(
                f'guide lifecycle plugin {plugin_asset}',
                src.read_text(encoding='utf-8'),
                dst,
            )
        else:
            note('FAIL',f'source guide lifecycle plugin asset missing: {plugin_asset}')
    collaboration_state_path=H/'state'/'john-lomein-collaboration-policy.json'
    try:
        if collaboration_state_path.is_symlink() or not collaboration_state_path.is_file():
            raise ValueError('collaboration policy state missing or unsafe')
        collaboration_stat=collaboration_state_path.stat()
        if collaboration_stat.st_uid != os.geteuid() or collaboration_stat.st_nlink != 1 or collaboration_stat.st_mode & 0o077:
            raise ValueError('collaboration policy state permissions are unsafe')
        collaboration_state=json.loads(collaboration_state_path.read_text(encoding='utf-8'))
        expected_state={**collaboration,'policy_sha256':sha256_json(collaboration)}
        if collaboration_state != expected_state:
            raise ValueError('collaboration policy state drift')
        note('OK','collaboration policy receipt is exact and fail-closed')
    except (OSError,ValueError,json.JSONDecodeError) as exc:
        note('FAIL',f'collaboration policy receipt invalid: {exc}')
    gh_guard=H/'scripts/bin/gh'
    if gh_guard.exists() and os.access(gh_guard, os.X_OK):
        note('OK','gh duplicate-review guard wrapper installed')
    else:
        note('FAIL','gh duplicate-review guard wrapper missing or not executable')
    git_guard=H/'scripts/bin/git'
    if git_guard.exists() and os.access(git_guard, os.X_OK):
        note('OK','git remote-mutation guard wrapper installed')
    else:
        note('FAIL','git remote-mutation guard wrapper missing or not executable')
    broker_public_config=Path('/private/etc/john-lomein-broker-public')/f'{slug}.json'
    if broker_public_config.exists() and not broker_public_config.is_symlink():
        try:
            parent_info=broker_public_config.parent.lstat()
            info=broker_public_config.lstat()
            raw=broker_public_config.read_bytes()
            public=json.loads(raw)
            expected_client_fields={
                'schema_version','broker_id','broker_uid','broker_config_sha256',
                'socket_path','public_key_path','public_key_sha256','key_id',
                'connect_timeout_seconds','request_timeout_seconds',
                'max_response_bytes','instance_slug','repository_full_name',
                'repository_id','default_branch','github_app_id',
                'github_app_slug','github_installation_id',
            }
            config_ok=(
                stat.S_ISDIR(parent_info.st_mode)
                and not stat.S_ISLNK(parent_info.st_mode)
                and parent_info.st_uid==0
                and not (parent_info.st_mode & 0o022)
                and stat.S_ISREG(info.st_mode)
                and info.st_uid==0
                and not (info.st_mode & 0o022)
                and len(raw)<=64*1024
                and isinstance(public,dict)
                and set(public)==expected_client_fields
                and public.get('schema_version')=='john-lomein.protected-broker-client-config.v1'
                and public.get('instance_slug')==slug
                and public.get('repository_full_name')==repo
                and public.get('default_branch')==branch
                and type(public.get('broker_uid')) is int
                and public.get('broker_uid')!=os.getuid()
                and type(public.get('repository_id')) is int
                and type(public.get('github_app_id')) is int
                and type(public.get('github_installation_id')) is int
                and bool(re.fullmatch(r'[0-9a-f]{64}',str(public.get('broker_config_sha256') or '')))
                and bool(re.fullmatch(r'[0-9a-f]{64}',str(public.get('public_key_sha256') or '')))
            )
            socket_path=Path(str(public.get('socket_path') or ''))
            public_key_path=Path(str(public.get('public_key_path') or ''))
            key_ok=False
            if config_ok and public_key_path.is_absolute() and not public_key_path.is_symlink():
                try:
                    key_info=public_key_path.lstat()
                    key_raw=public_key_path.read_bytes()
                    key_ok=(
                        stat.S_ISREG(key_info.st_mode)
                        and key_info.st_uid==0
                        and not (key_info.st_mode & 0o022)
                        and len(key_raw)<=64*1024
                        and hashlib.sha256(key_raw).hexdigest()==public.get('public_key_sha256')
                    )
                except OSError:
                    key_ok=False
            socket_ok=False
            if config_ok and key_ok and socket_path.is_absolute() and not socket_path.is_symlink():
                try:
                    socket_info=socket_path.lstat()
                    socket_ok=(
                        stat.S_ISSOCK(socket_info.st_mode)
                        and socket_info.st_uid==public.get('broker_uid')
                        and not (socket_info.st_mode & 0o007)
                    )
                except OSError:
                    socket_ok=False
            if config_ok and key_ok and socket_ok:
                note('OK','protected-action broker public trust config and authenticated socket are present')
            elif config_ok and key_ok:
                note('WARN' if effective_authority['mutation'] else 'OK','protected-action broker trust config is installed but daemon socket is unavailable; protected actions remain fail-closed')
            else:
                note('FAIL','protected-action broker public trust config is unsafe or bound to another instance/repository')
        except Exception as exc:
            note('FAIL',f'protected-action broker public trust config is unreadable: {exc}')
    elif broker_public_config.is_symlink():
        note('FAIL','protected-action broker public trust config is a symlink')
    else:
        note('WARN' if effective_authority['mutation'] else 'OK','protected-action broker not installed; draft promotion and outdated-thread resolution remain fail-closed')
    workflow_report=H/'state/john-lomein-native-workflows.json'
    note('OK' if workflow_report.exists() else 'FAIL', f'native workflow deployment report present: {workflow_report}' if workflow_report.exists() else f'native workflow deployment report missing: {workflow_report}')
    script_env=H/'scripts/john-lomein-instance.env'
    script_env_text=script_env.read_text(encoding='utf-8', errors='ignore') if script_env.exists() else ''
    note('OK' if f"BOT_IMPLEMENTATION_MODE='{implementation_mode(bot)}'" in script_env_text else 'FAIL', f'implementation mode exported: {implementation_mode(bot)}' if f"BOT_IMPLEMENTATION_MODE='{implementation_mode(bot)}'" in script_env_text else 'implementation mode not exported to script env')
    note('OK' if f"BOT_IMPLEMENTATION_EXECUTOR='{implementation_executor(bot)}'" in script_env_text else 'FAIL', f'implementation executor exported: {implementation_executor(bot)}' if f"BOT_IMPLEMENTATION_EXECUTOR='{implementation_executor(bot)}'" in script_env_text else 'implementation executor not exported to script env')
    note('OK' if "BOT_LEARNING_STEWARD_PROFILE='" in script_env_text and "BOT_LEARNING_CADENCE='" in script_env_text else 'FAIL', 'learning steward profile/cadence exported' if "BOT_LEARNING_STEWARD_PROFILE='" in script_env_text and "BOT_LEARNING_CADENCE='" in script_env_text else 'learning steward env exports missing')
    note(
        'OK'
        if "BOT_HERMES_MANAGED_ROOT='" in script_env_text
        and 'MNEMOSYNE_DATA_DIR=' not in script_env_text
        else 'FAIL',
        'runtime exports managed-policy root without model-facing Mnemosyne data'
        if "BOT_HERMES_MANAGED_ROOT='" in script_env_text
        and 'MNEMOSYNE_DATA_DIR=' not in script_env_text
        else 'runtime managed-policy export is missing or shared Mnemosyne data leaked',
    )
    boundary_env_ok=(
        f"BOT_MODEL_MEMORY_ISOLATION='{contract['model_memory_isolation']}'" in script_env_text
        and f"BOT_STEWARD_PRIVATE_ROOT='{H/'private'/'learning-steward'}'" in script_env_text
        and f"BOT_STEWARD_PROJECTION_ROOT='{H/'state'/'learning'}'" in script_env_text
    )
    note(
        'OK' if boundary_env_ok else 'FAIL',
        'runtime exports the exact required model/steward OS boundary'
        if boundary_env_ok
        else 'runtime model/steward OS-boundary exports are missing or non-canonical',
    )
    note('OK' if "BOT_AUTONOMY_POLICY_JSON='" in script_env_text else 'FAIL', 'autonomy policy exported to runtime script env' if "BOT_AUTONOMY_POLICY_JSON='" in script_env_text else 'autonomy policy runtime env export missing')
    owner_override=contract['owner_override']
    owner_override_env_expected={
        'BOT_OWNER_GITHUB_LOGINS':','.join(contract['owner_github_logins']),
        'BOT_OWNER_OVERRIDE_ENABLED':'1' if owner_override['enabled'] else '0',
        'BOT_OWNER_OVERRIDE_KEY_ID':owner_override['key_id'],
        'BOT_OWNER_OVERRIDE_PUBLIC_KEY_SHA256':owner_override['public_key_sha256'],
        'BOT_OWNER_OVERRIDE_DISCORD_USER_IDS':','.join(owner_override['allowed_discord_user_ids']),
    }
    owner_override_env_ok=all(f"{key}='{value}'" in script_env_text for key,value in owner_override_env_expected.items())
    note('OK' if owner_override_env_ok else 'FAIL', 'owner override policy exported exactly' if owner_override_env_ok else 'owner override runtime env exports missing or stale')
    owner_override_root=H/'private'/'owner-overrides'
    owner_override_inbox=owner_override_root/'inbox'
    owner_override_inbox_ok=safe_runtime_directory(owner_override_root) and safe_runtime_directory(owner_override_inbox)
    note('OK' if owner_override_inbox_ok else 'FAIL', 'owner override inbox is private and non-symlinked' if owner_override_inbox_ok else 'owner override inbox is missing or unsafe')
    owner_override_key=owner_override_root/'owner-override.public.pem'
    owner_override_key_ok=(not owner_override['enabled']) or (
        safe_runtime_public_key(owner_override_key)
        and hashlib.sha256(owner_override_key.read_bytes()).hexdigest()==owner_override['public_key_sha256']
    )
    note('OK' if owner_override_key_ok else 'FAIL', 'owner override verification key is inactive or safe' if owner_override_key_ok else 'enabled owner override verification key is missing or unsafe')
    honcho_state_ok=safe_runtime_directory(H/'state'/'honcho')
    honcho_tombstone_root=H/'private'/'honcho-deletion-tombstones'
    honcho_tombstones_ok=safe_runtime_directory(honcho_tombstone_root)
    note('OK' if honcho_state_ok and honcho_tombstones_ok else 'FAIL', 'Honcho pause and tombstone directories are private' if honcho_state_ok and honcho_tombstones_ok else 'Honcho pause or tombstone directory is missing or unsafe')
    tombstone_entries=list(honcho_tombstone_root.iterdir()) if honcho_tombstones_ok else []
    note('OK' if not tombstone_entries else 'FAIL', 'no deletion tombstone blocks service use' if not tombstone_entries else 'deletion tombstone replay is required before service use')
    pause_path=H/'state'/'honcho'/'INGESTION_PAUSED.json'
    pause_safe=(not pause_path.exists()) or safe_runtime_public_key(pause_path)
    note('OK' if pause_safe else 'FAIL', 'Honcho ingestion pause receipt is absent or private' if pause_safe else 'Honcho ingestion pause receipt is unsafe')
    pause_write_gate=True
    if pause_path.exists():
        try:
            guide_honcho=json.loads((H/'profiles'/str(profiles.get('guide') or '')/'honcho.json').read_text(encoding='utf-8'))
            hosts=guide_honcho.get('hosts')
            pause_write_gate=isinstance(hosts,dict) and bool(hosts) and all(isinstance(host,dict) and host.get('saveMessages') is False for host in hosts.values())
        except Exception:
            pause_write_gate=False
    note('OK' if pause_write_gate else 'FAIL', 'paused Guide cannot save Honcho messages' if pause_write_gate else 'pause receipt exists but Guide Honcho writes are not disabled')
    review_quorum=contract['review_quorum']
    review_quorum_json=json.dumps(review_quorum,sort_keys=True,separators=(',',':'))
    review_quorum_env_ok=f"BOT_REVIEW_QUORUM_POLICY_JSON='{review_quorum_json}'" in script_env_text
    note('OK' if review_quorum_env_ok else 'FAIL', 'review quorum policy exported exactly' if review_quorum_env_ok else 'review quorum runtime env export missing or stale')
    review_profiles_qualified = bool(contract['flags']['review_only_profiles_qualified'])
    expected_review_qualification = "1" if review_profiles_qualified else "0"
    review_env_ok = f"BOT_REVIEW_ONLY_PROFILES_QUALIFIED='{expected_review_qualification}'" in script_env_text
    review_safety_ok = review_env_ok and (not effective_authority['mutation'] or review_profiles_qualified)
    note(
        'OK' if review_safety_ok else 'FAIL',
        (
            'review-only profile qualification matches the manifest'
            if review_safety_ok
            else 'mutation requires explicitly qualified review-only profiles'
        ),
    )
    review_receipts_ok=safe_runtime_directory(H/'private'/'review-receipts')
    release_bundles_ok=safe_runtime_directory(H/'private'/'release-bundles')
    review_runs_ok=safe_runtime_directory(H/'state'/'review-runs')
    note('OK' if review_receipts_ok and release_bundles_ok else 'FAIL', 'review receipts and release bundles are private' if review_receipts_ok and release_bundles_ok else 'review receipt or release bundle directory is missing or unsafe')
    note('OK' if review_runs_ok else 'FAIL', 'review run directory is private and non-symlinked' if review_runs_ok else 'review run directory is missing or unsafe')
    try:
        deployed_review_quorum=json.loads((H/'state'/'john-lomein-review-quorum-policy.json').read_text(encoding='utf-8'))
    except Exception:
        deployed_review_quorum=None
    note('OK' if deployed_review_quorum==review_quorum else 'FAIL', 'review quorum deployment receipt is exact' if deployed_review_quorum==review_quorum else 'review quorum deployment receipt missing or stale')
    mission_env_keys=['BOT_MISSION_OWNER_AUTHORED_DECLARED','BOT_MISSION_OWNER_AUTHORED','BOT_MISSION_COMPLETE','BOT_MISSION_STATEMENT','BOT_MISSION_ROADMAP_SOURCES_JSON','BOT_MISSION_OWNER_SIGNAL_POLICY','BOT_MISSION_PERSONALITY_VOICE','BOT_MISSION_PERSONALITY_CREATIVE_POSTURE']
    mission_env_ok=(
        all(f"{key}='" in script_env_text for key in mission_env_keys)
        and f"BOT_MISSION_OWNER_AUTHORED_DECLARED='{'1' if flags['mission_owner_authored'] else '0'}'" in script_env_text
        and f"BOT_MISSION_OWNER_AUTHORED='{'1' if mission_complete else '0'}'" in script_env_text
        and f"BOT_MISSION_COMPLETE='{'1' if mission_complete else '0'}'" in script_env_text
    )
    note('OK' if mission_env_ok else 'FAIL', 'public-safe mission card and effective mission gate exported to runtime script env' if mission_env_ok else 'mission card or effective mission-gate runtime env exports missing or stale')
    authority_env_expected={
        'BOT_REQUESTED_ACTIVATION':requested_authority['activation'],
        'BOT_ACTIVATION':effective_authority['activation'],
        'BOT_MUTATION_REQUESTED':'1' if requested_authority['mutation'] else '0',
        'BOT_MUTATION_ENABLED':'1' if effective_authority['mutation'] else '0',
        'BOT_DISCORD_REQUESTED':'1' if requested_authority['discord'] else '0',
        'BOT_DISCORD_ENABLED':'1' if effective_authority['discord'] else '0',
        'BOT_GUIDE_GATEWAY_REQUESTED':'1' if requested_authority['guide_gateway'] else '0',
        'BOT_GUIDE_GATEWAY_ENABLED':'1' if effective_authority['guide_gateway'] else '0',
        'BOT_PROTECTED_RELEASE_BROKER_REQUESTED':'1' if requested_authority['protected_release'] else '0',
        'BOT_PROTECTED_RELEASE_BROKER_ENABLED':'1' if effective_authority['protected_release'] else '0',
        'BOT_OSC_PORTFOLIO_REQUESTED':'1' if requested_authority['portfolio'] else '0',
        'BOT_OSC_PORTFOLIO_ENABLED':'1' if effective_authority['portfolio'] else '0',
    }
    authority_env_ok=all(
        f"{key}='{value}'" in script_env_text
        for key,value in authority_env_expected.items()
    )
    note(
        'OK' if authority_env_ok else 'FAIL',
        'requested and effective authority projections exported to runtime script env'
        if authority_env_ok
        else 'requested/effective authority runtime env exports missing or stale',
    )
    note('OK' if f"BOT_NPM_TAG='{npm_tag}'" in script_env_text else 'FAIL', f'release npm dist-tag exported: {npm_tag}' if f"BOT_NPM_TAG='{npm_tag}'" in script_env_text else 'release npm dist-tag runtime env export missing or stale')
    note('OK' if f"BOT_PUBLISH_WORKFLOW='{publish_workflow}'" in script_env_text else 'FAIL', f'publish workflow exported: {publish_workflow}' if f"BOT_PUBLISH_WORKFLOW='{publish_workflow}'" in script_env_text else 'publish workflow runtime env export missing or stale')
    expected_portfolio_flag='1' if effective_authority['portfolio'] else '0'
    portfolio_env_ok=(
        f"BOT_OSC_PORTFOLIO_ENABLED='{expected_portfolio_flag}'" in script_env_text
        and "BOT_OSC_PORTFOLIO_CADENCE='" in script_env_text
    )
    note('OK' if portfolio_env_ok else 'FAIL', f'OSC portfolio effective gate exported: {expected_portfolio_flag}' if portfolio_env_ok else 'OSC portfolio effective gate or cadence export missing or stale')
    check_omh_bridge(bot,H,env,omh_catalog)
    runtime_python=resolve_hermes_python(env,H)
    qc,qo,qe=sh([runtime_python,str(H/'scripts/john-lomein-queue-health.py')],env=env,timeout=120)

    if qc==0:
        note('OK',f'queue health has no stuck PR blockers: {qo}')
    elif qc==1:
        note('WARN',f'queue health reports actionable/stuck blocker: {qo}')
    else:
        note('FAIL',f'queue health failed: {qe or qo}')
    wc,wo,we=sh([runtime_python,str(H/'scripts/john-lomein-worker.py'),'status'],env=env,timeout=45)
    if wc==0:
        note('OK',f'worker supervisor status readable: {wo[:260]}')
    else:
        note('FAIL',f'worker supervisor status failed: {we or wo}')
    if flags['learning_enabled']:
        lc,lo,le=sh([runtime_python,str(H/'scripts/john-lomein-learning-steward.py'),'smoke','--json'],env=env,timeout=180)
        if lc==0:
            try:
                ld=json.loads(lo or '{}')
                note('OK' if ld.get('ok') else 'FAIL', f"learning steward smoke ok brief={ld.get('brief_ok')} memory={ld.get('memory_ok')}")
            except Exception:
                note('WARN',f'learning steward smoke output unreadable: {lo[:220]}')
        else:
            note('FAIL',f'learning steward smoke failed: {le or lo}')
    else:
        note('OK','learning steward disabled; cron and smoke are not required')
    rc,ro,re=sh([runtime_python,str(H/'scripts/john-lomein-release-bundler.py')],env=env,timeout=120)
    if rc==0:
        note('OK',f'release bundle gate refresh works: {ro}')
    else:
        note('FAIL',f'release bundle gate refresh failed: {re or ro}')
    ec,eo,ee=sh([runtime_python,str(H/'scripts/john-lomein-release-executor.py'),'--dry-run'],env=env,timeout=180)
    if ec==0:
        try:
            ed=json.loads(eo or '{}')
            blockers=ed.get('blockers') or []
            if blockers:
                note('WARN',f"release executor dry-run blockers: {blockers[:3]}")
            else:
                note('OK',f"release executor dry-run ready: bundle={ed.get('bundle_id')} ready_prs={ed.get('ready_prs')}")
        except Exception:
            note('WARN',f'release executor dry-run output unreadable: {eo[:220]}')
    else:
        note('FAIL',f'release executor dry-run failed: {ee or eo}')
    pc,po,pe=sh([runtime_python,str(H/'scripts/john-lomein-release-approve.py'),'status'],env=env,timeout=45)
    try:
        protected_status=json.loads(po or '{}')
    except Exception:
        protected_status={}
    if effective_authority['protected_release']:
        note(
            'OK' if pc==0 and protected_status.get('ready') is True else 'FAIL',
            'protected release owner gateway and broker are ready'
            if pc==0 and protected_status.get('ready') is True
            else f'protected release path is enabled but unavailable: {pe or po}',
        )
    else:
        disabled_safe=(
            pc==0
            and protected_status.get('runtime_route_enabled') is False
            and protected_status.get('unexpected_privileged_surface') is False
        )
        note(
            'OK' if disabled_safe else 'FAIL',
            'protected release runtime route is disabled and no privileged signer authorization or broker listener is exposed'
            if disabled_safe
            else f'protected release disabled-canary found an exposed or unreadable privileged surface: {pe or po}',
        )
    if effective_authority['discord']:
        dc,do,de=sh(['bash',str(H/'scripts/john-lomein-overwatch-post.sh'),'DOCTOR_DRY_RUN','notification route check'],env={**env,'JOHN_LOMEIN_NOTIFY_DRY_RUN':'1'},timeout=45)
        note('OK' if dc==0 and 'dry-run notify' in do else 'FAIL', f'notification route dry-run works: {do}' if dc==0 and 'dry-run notify' in do else f'notification route dry-run failed: {de or do}')
    c,o,e=sh(['hermes','cron','list','--all'],timeout=40)
    if c==0:
        leaked=[]
        cron_names=[f'john-lomein-{slug}-watchdog',f'john-lomein-{slug}-maintainer',f'john-lomein-{slug}-forge-cycle',f'john-lomein-{slug}-overwatch',f'john-lomein-{slug}-learning-steward']
        if requested_authority['portfolio']:
            cron_names.append(f'john-lomein-{slug}-osc-portfolio')
        for name in cron_names:
            if name in o: leaked.append(name)
        note('OK' if not leaked else 'FAIL', 'no instance crons leaked into default Hermes runtime' if not leaked else f'instance crons leaked into default Hermes: {leaked}')
    else: note('WARN',f'default cron list unavailable: {e or o}')
    scheduler_label=f'ai.hermes.john-lomein-{slug}-scheduler'
    scheduler_required=effective_authority['scheduler_required']
    if scheduler_required:
        note('OK' if launch_loaded(scheduler_label) else 'FAIL', f'scheduler LaunchAgent loaded: {scheduler_label}' if launch_loaded(scheduler_label) else f'scheduler LaunchAgent missing: {scheduler_label}')
        check_launchagent_model_environment(
            scheduler_label,
            role_profiles['maintainer'],
            H,
        )
    else:
        note('OK' if not launch_loaded(scheduler_label) else 'FAIL', f'scheduler LaunchAgent not required while owner-gated' if not launch_loaded(scheduler_label) else f'scheduler LaunchAgent loaded while owner-gated: {scheduler_label}')
    keep_label=f'ai.hermes.john-lomein-{slug}-keepawake'
    if flags['runtime_keep_awake_on_ac']:
        note('OK' if launch_loaded(keep_label) else 'WARN', f'keepawake LaunchAgent loaded: {keep_label}' if launch_loaded(keep_label) else f'keepawake requested but LaunchAgent missing: {keep_label}')
    guide_label=f'ai.hermes.gateway-john-lomein-{slug}-guide'
    guide_required=effective_authority['guide_required']
    if guide_required:
        note('OK' if launch_loaded(guide_label) else 'FAIL', f'guide gateway LaunchAgent loaded: {guide_label}' if launch_loaded(guide_label) else f'guide gateway LaunchAgent missing: {guide_label}')
        check_launchagent_model_environment(
            guide_label,
            role_profiles['guide'],
            H,
            require_isolation=True,
        )
    else:
        note('OK' if not launch_loaded(guide_label) else 'FAIL', f'guide gateway owner-gated/not loaded' if not launch_loaded(guide_label) else f'guide gateway loaded despite owner gate: {guide_label}')
    expected_services={}
    if scheduler_required:
        expected_services['scheduler']=scheduler_label
    if flags['runtime_keep_awake_on_ac']:
        expected_services['keepawake']=keep_label
    if guide_required:
        expected_services['guide']=guide_label
    try:
        service_status=registry_status(manifest,H,expected_services)
        note(
            'OK' if not service_status['issues'] else 'FAIL',
            'launchd service registry matches this instance and runtime'
            if not service_status['issues']
            else (
                'launchd service registry drift: '
                f"issues={service_status['issues']} "
                f"registered={service_status['registered']} "
                f"missing={service_status['missing']} "
                f"identity_mismatches={service_status['identity_mismatches']} "
                f"conflicting={service_status['conflicting']} "
                f"unexpected={service_status['unexpected']}"
            ),
        )
    except Exception as exc:
        note('FAIL',f'launchd service registry inspection failed: {exc}')
    if effective_authority['mutation']:
        note('OK','mutation lanes enabled by instance manifest and owner approval; effectiveness still requires fresh repo-moving evidence or exact blockers')
    elif requested_authority['mutation']:
        note('OK','mutation lanes were requested but remain blocked by the incomplete owner mission')
    else:
        note('OK','mutation lanes owner-gated/disabled; installed health is not repo effectiveness')
    if effective_authority['discord']:
        if guide_required:
            note('OK','public Discord guide exposure enabled by instance manifest; requires separate token/channel smoke')
        else:
            note('OK','Discord channel config present but public guide gateway remains owner-gated')
    elif requested_authority['discord']:
        note('OK','public Discord exposure was requested but remains blocked by the incomplete owner mission')
    else:
        note('OK','public Discord guide exposure owner-gated/disabled')
    print('\nalive_vs_effective:')
    print('  alive: five generic profiles, profile-local skills, crons, bounded tool surfaces, checkout, and auth are installed' if not FAIL else '  alive: incomplete')
    print('  effective: repo mutation/public Discord are owner-gated unless explicitly enabled; doctor does not count liveness as repo movement')
    print('\nsummary:')
    print(f'  failures={len(FAIL)} warnings={len(WARN)}')
    return diagnostic_exit_code()
if __name__=='__main__': raise SystemExit(main())
