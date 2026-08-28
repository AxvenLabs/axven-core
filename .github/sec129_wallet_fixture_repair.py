#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "wallet_persistence_cli_test.py"
MANIFEST = ROOT / "release_manifest.json"
WORKFLOW = ROOT / ".github" / "workflows" / "sec129-wallet-fixture-repair.yml"
SELF = Path(__file__).resolve()

src = TARGET.read_text(encoding="utf-8")
old = '''    ed=axven.Wallet()\n    ident=wallet.WalletIdentity(\n        ed_keypair=(ed.public_key,ed.private_key),\n        ml_keypair=(b"\\x51"*1312,b"\\x61"*2560)\n    )\n'''
new = '''    ed=axven.Wallet()\n    ml=axven.MLDSAWallet()\n    ident=wallet.WalletIdentity(\n        ed_keypair=(ed.public_key,ed.private_key),\n        ml_keypair=(ml.public_key,ml._secret)\n    )\n'''
assert src.count(old) == 1, "SEC-129 wallet CLI fixture anchor changed"
src = src.replace(old, new, 1)
TARGET.write_text(src, encoding="utf-8", newline="\n")

manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
for rel in (
    "daemon_lifecycle_test.py",
    "wallet_persistence_cli_test.py",
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
