#!/usr/bin/env python3
"""Stage rendered, installable John Lomein profile distributions."""
from __future__ import annotations

import os
import re
import shutil
import stat
import sys
from pathlib import Path

PLACEHOLDER_RE=re.compile(r'\{\{[A-Z0-9_]+\}\}')

def _safe_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f'unsafe distribution directory symlink: {path}')
    if path.exists():
        info=path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError(f'unsafe distribution directory metadata: {path}')

def stage(product: Path, runtime: Path, distribution: str, configured_profile: str) -> Path:
    for value in (distribution,configured_profile):
        if not value or Path(value).name != value or value in {'.','..'}:
            raise ValueError('unsafe profile distribution name')
    source=product/'profiles'/distribution
    manifest=source/'distribution.yaml'
    rendered_soul=runtime/'profiles'/configured_profile/'SOUL.md'
    if not manifest.is_file() or not rendered_soul.is_file():
        raise ValueError('profile distribution source or rendered SOUL is incomplete')
    rendered=rendered_soul.read_text(encoding='utf-8')
    unresolved=sorted(set(PLACEHOLDER_RE.findall(rendered)))
    if unresolved:
        raise ValueError(f'rendered profile SOUL contains placeholders: {unresolved}')
    root=runtime/'distributions'
    target=root/distribution
    temporary=root/f'.{distribution}.staging-{os.getpid()}'
    for path in (root,target,temporary):
        _safe_directory(path)
    root.mkdir(parents=True,exist_ok=True,mode=0o700)
    if temporary.exists():
        shutil.rmtree(temporary)
    temporary.mkdir(mode=0o700)
    shutil.copy2(manifest,temporary/'distribution.yaml')
    (temporary/'SOUL.md').write_text(rendered.rstrip()+'\n',encoding='utf-8')
    os.chmod(temporary/'SOUL.md',0o600)
    os.chmod(temporary/'distribution.yaml',0o600)
    if target.exists():
        shutil.rmtree(target)
    os.replace(temporary,target)
    return target

def main(argv: list[str]) -> int:
    if len(argv)!=4:
        print('usage: stage_profile_distribution.py PRODUCT RUNTIME DISTRIBUTION PROFILE',file=sys.stderr)
        return 2
    try:
        path=stage(Path(argv[0]).resolve(),Path(argv[1]).resolve(),argv[2],argv[3])
    except (OSError,ValueError) as exc:
        print(str(exc),file=sys.stderr)
        return 2
    print(path)
    return 0


if __name__=='__main__':
    raise SystemExit(main(sys.argv[1:]))
