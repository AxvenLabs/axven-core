#!/usr/bin/env python3
"""Run release validation sequentially; intended for the user's real machine."""
from __future__ import annotations
import json, subprocess, sys, time
from pathlib import Path

ROOT=Path(__file__).resolve().parent
SUITES=[
 ("pq_dependency_check.py","PQ dependency smoke"),
 ("pq_real_validation.py","PQ M/H end-to-end"),
 ("wallet_integration_spec_test.py","W-003 wallet integration"),
 ("release_packaging_test.py","Release packaging"),
 ("daemon_lifecycle_test.py","Daemon lifecycle"),
 ("wallet_persistence_cli_test.py","Wallet persistence/CLI"),
 ("core_rpc_test.py","Core/RPC"),
 ("p2p_tcp_lifecycle_test.py","P2P TCP lifecycle"),
 ("devnet_rehearsal.py","Two-node devnet rehearsal"),
 ("checkpoint42_peer_reconnect_spec.py","Persistent peer reconnect/recovery"),
 ("activation_record_encoding_test.py","Activation record UTF-8"),
 ("post_activation_audit.py","Post-activation audit"),
 ("p2p_spec_test.py","P2P spec"),
 ("consensus_rebuild_test.py","Consensus rebuild"),
 ("smt_incremental_test.py","Incremental SMT"),
]

def main():
    rows=[]; all_ok=True
    for script,name in SUITES:
        print(f"\n=== {name} ===",flush=True)
        t=time.perf_counter()
        p=subprocess.run([sys.executable,script],cwd=ROOT,text=True)
        sec=time.perf_counter()-t
        ok=p.returncode==0
        rows.append({"name":name,"script":script,"ok":ok,"seconds":round(sec,3)})
        all_ok &= ok
        if not ok:
            print(f"\nSTOP: {name} failed.",flush=True)
            break
    print("\n=== AXVEN VALIDATION SUMMARY ===")
    print(json.dumps({"ok":all_ok,"results":rows},indent=2))
    raise SystemExit(0 if all_ok else 1)

if __name__=="__main__":main()
