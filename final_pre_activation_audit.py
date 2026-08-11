#!/usr/bin/env python3
"""Checkpoint 17 final pre-activation audit.

Read-only release gate. It does not execute activation and does not mutate
CHAIN_CONFIG, genesis, chain state, wallet state, or datadirs.
"""
from pathlib import Path
import json
import axven

ROOT=Path(__file__).resolve().parent
EXPECTED_CHAIN_ID="axven-devnet-2"
EXPECTED_FP="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
EXPECTED_GENESIS="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"

checks=[]
def check(name, cond):
    if not cond: raise AssertionError(name)
    checks.append(name)
    print(f"[GREEN] {name}")

check("chain id pin", axven.CHAIN_ID == EXPECTED_CHAIN_ID)
check("config fingerprint pin", axven.CONFIG_FINGERPRINT == EXPECTED_FP)
check("genesis hash pin", axven._genesis().hash() == EXPECTED_GENESIS)

m=json.loads((ROOT/"release_manifest.json").read_text())
check("manifest activation not executed", m.get("activation") == "NOT_EXECUTED")
check("manifest chain id", m.get("chain_id") == EXPECTED_CHAIN_ID)
check("manifest fingerprint", m.get("config_fingerprint") == EXPECTED_FP)
check("manifest genesis", m.get("genesis_hash") == EXPECTED_GENESIS)

required=[
 "axven.py","wallet.py","p2p.py","core.py","rpc.py","datadir.py",
 "axven_core.py","axven_cli.py","doctor.py",
 "pq_real_validation.py","wallet_integration_spec_test.py",
 "daemon_lifecycle_test.py","wallet_persistence_cli_test.py",
 "core_rpc_test.py","p2p_tcp_lifecycle_test.py","devnet_rehearsal.py",
 "RELEASE_CANDIDATE.md","DEVNET_REHEARSAL.md"
]
for name in required:
    check("release file "+name, (ROOT/name).is_file())

print(json.dumps({
 "ok": True,
 "checks": len(checks),
 "chain_id": EXPECTED_CHAIN_ID,
 "fingerprint": EXPECTED_FP,
 "genesis_hash": EXPECTED_GENESIS,
 "activation": "NOT_EXECUTED",
 "gate": "FINAL_PRE_ACTIVATION_AUDIT"
}, indent=2, sort_keys=True))
