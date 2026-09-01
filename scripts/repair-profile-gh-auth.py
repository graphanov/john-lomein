#!/usr/bin/env python3
from __future__ import annotations
import argparse, os, shutil, subprocess, sys
from pathlib import Path
try:
    import yaml
except Exception:
    yaml=None
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_profile_contract import canonical_role_profiles

def load_instance(arg: str):
    p=Path(arg).expanduser()
    if p.is_dir():
        m=p/'instance.yaml'
        if not m.exists(): m=p/'bot.yaml'
    else:
        m=p
    if yaml is None or not m.exists(): return {}, p
    return yaml.safe_load(m.read_text(encoding='utf-8')) or {}, m.parent

def parse_env(path: Path):
    vals={}
    if not path.exists(): return vals
    for raw in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        line=raw.strip()
        if not line or line.startswith('#') or '=' not in line: continue
        k,v=line.split('=',1); vals[k.strip()]=v.strip().strip('"').strip("'")
    return vals

def gh_home_env(home: Path):
    env=dict(os.environ); env.pop('GH_TOKEN',None); env.pop('GITHUB_TOKEN',None)
    env['HOME']=str(home); env['XDG_CONFIG_HOME']=str(home/'.config'); env['XDG_STATE_HOME']=str(home/'.local/state'); env['XDG_DATA_HOME']=str(home/'.local/share')
    env['GH_CONFIG_DIR']=str(home/'.config/gh')
    env['GH_PROMPT_DISABLED']='1'
    env['GH_NO_UPDATE_NOTIFIER']='1'
    env['GH_NO_EXTENSION_UPDATE_NOTIFIER']='1'
    return env

def token_from_hosts(home: Path) -> str:
    """Read an existing profile-local gh token without asking macOS Keychain.

    The value is never printed. This lets repair-profile-gh-auth.py clone auth
    from one already-repaired profile to another instead of calling root
    `gh auth token`, which can summon a Keychain prompt in LaunchAgent contexts.
    """
    hosts=home/'.config/gh/hosts.yml'
    if not hosts.exists():
        return ''
    for raw in hosts.read_text(encoding='utf-8', errors='ignore').splitlines():
        line=raw.strip()
        if line.startswith('oauth_token:'):
            token=line.split(':',1)[1].strip().strip('"').strip("'")
            return token if token.startswith(('gho_','ghp_','github_pat_')) else token
    return ''

def check(home: Path):
    r=subprocess.run(['gh','auth','status','--hostname','github.com'],capture_output=True,text=True,timeout=30,env=gh_home_env(home))
    return r.returncode==0 and 'Logged in to github.com' in (r.stdout+r.stderr)

def install(home: Path, token: str):
    home.mkdir(parents=True, exist_ok=True)
    r=subprocess.run(['gh','auth','login','--hostname','github.com','--with-token'],input=token+'\n',capture_output=True,text=True,timeout=30,env=gh_home_env(home))
    subprocess.run(['gh','auth','setup-git'],capture_output=True,text=True,timeout=30,env=gh_home_env(home))
    hosts=home/'.config/gh/hosts.yml'
    if hosts.exists(): os.chmod(hosts,0o600)
    return check(home)

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('instance')
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--allow-keychain-fallback', action='store_true', help='last-resort: allow root gh auth token lookup, which may prompt macOS Keychain')
    args=ap.parse_args()
    bot, idir=load_instance(args.instance)
    try:
        role_profiles=canonical_role_profiles(bot)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    runtime=bot.get('runtime') or {}; secrets=bot.get('secrets') or {}
    H=Path(os.path.expanduser(str(runtime.get('hermes_home') or os.environ.get('HERMES_HOME') or f'~/.john-lomein/instances/{(bot.get("instance") or {}).get("slug","unknown")}/hermes'))).resolve()
    names=[
        role_profiles[role]
        for role in ('maintainer','forge','overwatch','learning_steward')
    ]
    homes=[(name, H/'profiles'/name/'home') for name in names]
    guide_gh = (
        H
        / 'profiles'
        / role_profiles['guide']
        / 'home'
        / '.config'
        / 'gh'
    )
    if guide_gh.exists() and guide_gh.is_dir() and not guide_gh.is_symlink():
        shutil.rmtree(guide_gh)
    elif guide_gh.exists() or guide_gh.is_symlink():
        guide_gh.unlink()
    precheck={name: check(home) for name, home in homes}
    token=''
    if not args.check and not all(precheck.values()):
        for p in [H/'scripts'/'john-lomein-instance.env', H/'.env'] + [Path(os.path.expanduser(str(x))) for x in secrets.get('import_env_files') or []]:
            token=parse_env(p).get('GH_TOKEN','')
            if token: break
        if not token:
            for _, home in homes:
                token=token_from_hosts(home)
                if token: break
        if not token and args.allow_keychain_fallback:
            r=subprocess.run(['gh','auth','token','--hostname','github.com'],capture_output=True,text=True,timeout=30)
            if r.returncode==0: token=r.stdout.strip()
    ok_all=True
    for name, home in homes:
        ok=precheck.get(name, False) if args.check else (precheck.get(name, False) or (install(home, token) if token else check(home)))
        ok_all=ok_all and ok
        if not args.quiet or not ok:
            print(f"{'OK' if ok else 'WARN'} profile-gh-auth profile={name} home={home} token_value=redacted")
    return 0 if ok_all else 1
if __name__ == '__main__': raise SystemExit(main())
