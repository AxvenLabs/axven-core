#!/usr/bin/env python3
from pathlib import Path
import hashlib, json, sys
ROOT=Path(__file__).resolve().parent
m=json.loads((ROOT/"release_manifest.json").read_text(encoding="utf-8"))
bad=[]
checked=0
for name,meta in m.get("files",{}).items():
    p=ROOT/name
    if not p.exists():
        bad.append(f"missing: {name}"); continue
    got=hashlib.sha256(p.read_bytes()).hexdigest()
    checked+=1
    if got!=meta["sha256"]: bad.append(f"hash mismatch: {name}")
if bad:
    print("\n".join(bad)); raise SystemExit(2)
print(f"Release integrity: {checked}/{checked} GREEN")
