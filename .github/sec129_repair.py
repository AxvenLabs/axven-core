#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC128 = ROOT / "security_sec128_wallet_backup_json_preparse_depth_spec.py"
MANIFEST = ROOT / "release_manifest.json"
WORKFLOW = ROOT / ".github" / "workflows" / "sec129-repair.yml"
SELF = Path(__file__).resolve()

src = SPEC128.read_text(encoding="utf-8")
old = '        < restore_src.index("json.loads(plain)"),\n'
new = '        < restore_src.index("json.loads("),\n'
assert src.count(old) == 1, "SEC-128 parser-order assertion anchor changed"
src = src.replace(old, new, 1)
SPEC128.write_text(src, encoding="utf-8", newline="\n")

manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
for rel in (
    "security_sec128_wallet_backup_json_preparse_depth_spec.py",
    "security_sec129_wallet_inner_material_canonicality_spec.py",
    "wallet.py",
):
    data = (ROOT / rel).read_bytes()
    manifest["files"][rel] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
MANIFEST.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)

if WORKFLOW.exists():
    WORKFLOW.unlink()
if SELF.exists():
    SELF.unlink()
