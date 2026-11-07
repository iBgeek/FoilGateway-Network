#!/usr/bin/env python3
"""Extract the compile-time service asset. Never run an installer/service command."""
from pathlib import Path
import hashlib
root=Path(__file__).resolve().parents[1]
text=(root/'scripts/install.sh').read_text();payload=text.split("<<'UNIT'\n",1)[1].split('\nUNIT',1)[0]+'\n'
target=root/'dist/foilgw.service'
if target.exists() and target.read_bytes()!=payload.encode():raise SystemExit('Different dist/foilgw.service exists; preserve/reconcile it before building.')
target.parent.mkdir(exist_ok=True)
if not target.exists():target.write_text(payload)
print(hashlib.sha256(target.read_bytes()).hexdigest()+'  dist/foilgw.service')
