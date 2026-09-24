#!/usr/bin/env python3
"""ARCH-001 research-only canonical decision-evidence bundle."""
from __future__ import annotations
import hashlib, json, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIXTURES = (
    "arch001_invariants.py","arch001_transfer_compare.py","arch001_native_equivalence_evidence.py",
    "arch001_native_representation_delta_evidence.py","arch001_native_sequence_representation_delta_evidence.py",
    "arch001_native_sequence_summary_evidence.py","arch001_native_marginal_growth_evidence.py",
    "arch001_token_compare.py","arch001_token_program_compare.py","arch001_program_conflict_evidence.py",
    "arch001_program_reorg_evidence.py","arch001_program_sequence_evidence.py","arch001_program_auth_surface_evidence.py",
    "arch001_contention_compare.py","arch001_batch_order_compare.py","arch001_access_compare.py",
    "arch001_state_growth_compare.py","arch001_rollback_compare.py","arch001_migration_reuse_compare.py",
    "arch001_migration_reuse_summary_evidence.py","arch001_auth_size_evidence.py","arch001_native_measurement_evidence.py",
    "arch001_native_sequence_evidence.py","arch001_native_auth_surface_evidence.py","arch001_native_reorg_sequence_evidence.py",
    "arch001_evidence_coverage.py",
)

def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def run_fixture(name):
    path=ROOT/name; source=path.read_bytes()
    proc=subprocess.run([sys.executable,str(path)],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=60)
    return {"fixture":name,"source_bytes":len(source),"source_sha256":hashlib.sha256(source).hexdigest(),"exit_code":proc.returncode,"stdout_bytes":len(proc.stdout),"stdout_sha256":hashlib.sha256(proc.stdout).hexdigest(),"stderr_bytes":len(proc.stderr),"stderr_sha256":hashlib.sha256(proc.stderr).hexdigest()}

def build_bundle():
    rows=[run_fixture(name) for name in FIXTURES]
    assert all(row["exit_code"]==0 for row in rows)
    assert all(row["stderr_bytes"]==0 for row in rows)
    assert all(row["source_bytes"]>0 for row in rows)
    return {"schema":"axven-arch001-decision-evidence-v2","scope":"research-only; outside production consensus routing","candidates":["utxo","account-state","object-resource"],"fixtures":rows,"fixture_source_provenance_included":True,"required_evidence_coverage_bound":True,"native_workload_equivalence_bound":True,"native_representation_deltas_bound":True,"native_sequence_representation_deltas_bound":True,"native_sequence_summary_bound":True,"native_marginal_growth_bound":True,"migration_reuse_summary_bound":True,"excluded_nondeterministic_diagnostics":["arch001_auth_cost_compare.py:median_verify_ns"],"architecture_selected":False}

def main():
    first=build_bundle(); second=build_bundle(); a=canonical_bytes(first); b=canonical_bytes(second); assert a==b
    print("ARCH-001 canonical decision bundle: deterministic GREEN")
    print("bundle_sha256",hashlib.sha256(a).hexdigest()); print(a.decode("ascii"))
    print("NOTE deterministic research evidence is digest-bound; PQ/hybrid timing remains diagnostic; no architecture selected")
if __name__=="__main__": main()
