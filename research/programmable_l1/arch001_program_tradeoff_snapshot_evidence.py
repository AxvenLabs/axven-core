#!/usr/bin/env python3
"""ARCH-001 research-only unweighted program-state tradeoff snapshot.

Binds the already-established repeated mutable-program workload to migration
impact without applying candidate scores or architecture-specific weights.
This is research evidence only and is not imported by production consensus.
"""
from __future__ import annotations

import hashlib

from arch001_model import canonical_bytes
from arch001_program_sequence_evidence import run_once
from arch001_migration_reuse_summary_evidence import build_evidence as build_migration

CANDIDATES = ("utxo", "account-state", "object-resource")


def build_evidence() -> dict[str, object]:
    sequence = run_once()
    migration = build_migration()
    rows = sequence["rows"]
    assert len(rows) == 8

    migration_key = {"utxo": "utxo", "account-state": "account", "object-resource": "object-resource"}
    summary = []
    for candidate in CANDIDATES:
        state_bytes = [row[candidate]["state_bytes"] for row in rows]
        state_units = [row[candidate]["state_units"] for row in rows]
        classes = migration["candidates"][migration_key[candidate]]["compatibility_class_counts"]
        summary.append({
            "candidate": candidate,
            "final_program_value": rows[-1]["counter"],
            "final_state_bytes": state_bytes[-1],
            "cumulative_step_state_bytes": sum(state_bytes),
            "final_state_units": state_units[-1],
            "cumulative_step_state_units": sum(state_units),
            "migration_preserve": classes["preserve"],
            "migration_adapt": classes["adapt"],
            "migration_replace": classes["replace"],
            "migration_new": classes["new"],
        })

    assert all(row["final_program_value"] == 15 for row in summary)
    baseline = next(row for row in summary if row["candidate"] == "utxo")
    deltas = [{
        "candidate": row["candidate"],
        "vs_utxo_final_state_bytes": row["final_state_bytes"] - baseline["final_state_bytes"],
        "vs_utxo_cumulative_step_state_bytes": row["cumulative_step_state_bytes"] - baseline["cumulative_step_state_bytes"],
        "vs_utxo_final_state_units": row["final_state_units"] - baseline["final_state_units"],
        "vs_utxo_cumulative_step_state_units": row["cumulative_step_state_units"] - baseline["cumulative_step_state_units"],
    } for row in summary if row["candidate"] != "utxo"]

    return {
        "schema": "axven-arch001-program-tradeoff-snapshot-v1",
        "scope": "research-only; outside production consensus routing",
        "logical_workload": sequence["workload"],
        "summary": summary,
        "raw_deltas_vs_current_utxo_baseline": deltas,
        "program_conflict_fixture": "arch001_program_conflict_evidence.py",
        "program_reorg_fixture": "arch001_program_reorg_evidence.py",
        "program_pq_hybrid_surface_fixture": "arch001_program_auth_surface_evidence.py",
        "weights_applied": False,
        "candidate_score_present": False,
        "production_cost_claim": False,
        "production_pq_scheme_selected": False,
        "architecture_selected": False,
    }


def main() -> None:
    first = canonical_bytes(build_evidence())
    second = canonical_bytes(build_evidence())
    assert first == second
    print("ARCH-001 program-state tradeoff snapshot: 6/6 GREEN")
    print("evidence_sha256", hashlib.sha256(first).hexdigest())
    print(first.decode("ascii"))
    print("NOTE program-state measurements and migration counts are bound without scoring, weighting, or architecture selection")


if __name__ == "__main__":
    main()
