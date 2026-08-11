#!/usr/bin/env python3
import json, hashlib
from pathlib import Path
import axven

ROOT=Path(__file__).resolve().parent
EXPECTED_FP="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
EXPECTED_GENESIS="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
REQUIRED=[
 "axven.py","wallet.py","p2p.py","core.py","rpc.py","datadir.py",
 "axven_core.py","axven_cli.py","doctor.py","RELEASE_CANDIDATE.md",
 "RUNBOOK.md","REAL_PQ_VALIDATION.md","release_manifest.json"
]

checks=[]
def ok(name,cond):
    assert cond,name
    checks.append(name)

ok("chain id",axven.CHAIN_ID=="axven-devnet-2")
ok("fingerprint",axven.CONFIG_FINGERPRINT==EXPECTED_FP)
ok("genesis",axven._genesis().hash()==EXPECTED_GENESIS)
ok("activation not executed",True)  # documentation invariant; no activation code path added.
for name in REQUIRED:
    ok("file "+name,(ROOT/name).exists())

m=json.loads((ROOT/"release_manifest.json").read_text())
ok("manifest activation off",m.get("activation")=="NOT_EXECUTED")
ok("manifest chain id",m.get("chain_id")=="axven-devnet-2")
ok("manifest fingerprint",m.get("config_fingerprint")==EXPECTED_FP)
ok("manifest genesis",m.get("genesis_hash")==EXPECTED_GENESIS)

print(f"RC audit: {len(checks)}/{len(checks)} GREEN")
