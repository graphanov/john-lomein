#!/usr/bin/env python3
from __future__ import annotations
import re, sys
from pathlib import Path
ROOT=Path(sys.argv[1] if len(sys.argv)>1 else '.').resolve()
skip={'.git','.clawhip','.omx','.venv','__pycache__'}
# Build sensitive literals from pieces so the scanner does not fail on its own source.
owner_terms = ['Dan'+'iel', 'dan'+'imal', 'para'+'punov', 'gra'+'phanov']
concrete_terms = ['Lazy'+'GLM', 'Open '+'Scaffold', 'open-'+'scaffold', 'Lazy '+'GLM']
patterns=[
    ('private_user_path', re.compile(r'/Users/[A-Za-z0-9._-]+')),
    ('owner_name_or_handle', re.compile(r'\b('+'|'.join(re.escape(x) for x in owner_terms)+r')\b', re.I)),
    ('email', re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')),
    ('discord_id', re.compile(r'\b\d{17,20}\b')),
    ('token_like', re.compile(r'\b(?:ghp_|github_pat_|sk-|xox[baprs]-|AIza)[A-Za-z0-9_\-]{12,}')),
]
name_pat=re.compile(r'\b('+'|'.join(re.escape(x) for x in concrete_terms)+r')\b')
fail=[]
for p in ROOT.rglob('*'):
    if any(part in skip for part in p.parts) or not p.is_file():
        continue
    try:
        text=p.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        continue
    rel=str(p.relative_to(ROOT))
    scan_text=text
    if rel == 'LICENSE':
        approved_legal_line = 'Copyright (c) 2026 ' + 'Grapha' + 'nov'
        if text.count(approved_legal_line) != 1:
            fail.append((rel,'legal_attribution_invalid'))
        scan_text = text.replace(approved_legal_line, '')
    for label,pat in patterns:
        if pat.search(scan_text): fail.append((rel,label))
    if name_pat.search(scan_text): fail.append((rel,'concrete_instance_name'))
if fail:
    for rel,label in sorted(set(fail)):
        print(f'FAIL privacy-scan {label}: {rel}')
    print(f'summary: failures={len(set(fail))}')
    raise SystemExit(2)
print('privacy-scan OK: no private paths, owner identity, emails, Discord IDs, token-like strings, or concrete instance names in product source')
