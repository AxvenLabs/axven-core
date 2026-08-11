#!/usr/bin/env python3
import json, subprocess, sys, os
from pathlib import Path
import axven, doctor

ROOT=Path(__file__).resolve().parent

SUITES=[
    ("release_packaging_test.py","packaging"),
    ("daemon_lifecycle_test.py","daemon"),
    ("wallet_persistence_cli_test.py","wallet_persistence"),
    ("core_rpc_test.py","core_rpc"),
    ("p2p_tcp_lifecycle_test.py","p2p_tcp"),
    ("p2p_spec_test.py","p2p"),
    ("consensus_rebuild_test.py","consensus"),
    ("smt_incremental_test.py","smt"),
]

def run_suite(script):
    p=subprocess.run([sys.executable,script],cwd=ROOT,text=True,capture_output=True,timeout=240)
    return {"ok":p.returncode==0,"returncode":p.returncode,"stdout":p.stdout.strip(),
            "stderr":p.stderr.strip()[-2000:]}

def main():
    result={
      "chain_id":axven.CHAIN_ID,
      "config_fingerprint":axven.CONFIG_FINGERPRINT,
      "genesis_hash":axven._genesis().hash(),
      "activation":"NOT_EXECUTED",
      "suites":{},
    }
    all_ok=True
    for script,name in SUITES:
        r=run_suite(script)
        result["suites"][name]=r
        all_ok=all_ok and r["ok"]

    d=doctor.run()
    result["doctor"]=d
    pq_ready=d["checks"]["dilithium_py"]["ok"]

    # Release decision: local RC can be structurally green, but canonical PQ RC is gated
    # on the actual ML-DSA dependency and full W-003 M/H run.
    result["local_rc_green"]=all_ok
    result["pq_dependency_ready"]=pq_ready
    result["canonical_rc_ready"]=all_ok and pq_ready
    result["external_gates"]=[]
    if not pq_ready:
        result["external_gates"].append(
            "Install dilithium-py==1.4.0 and run the real ML-DSA/W-003 M/H suites; no fake backend allowed."
        )
    print(json.dumps(result,indent=2,sort_keys=True))
    raise SystemExit(0 if all_ok else 1)

if __name__=="__main__":main()
