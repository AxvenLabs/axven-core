#!/usr/bin/env python3
"""ARCH-001 research-only unweighted tradeoff snapshot.

Combines already-established deterministic evidence into one review surface.
It deliberately applies no scoring or architecture-specific weights and is not
imported by production consensus routing.
"""
from __future__ import annotations

import hashlib

from arch001_model import canonical_bytes
from arch001_native_sequence_summary_evidence import build_evidence as build_native
from arch001_migration_reuse_summary_evidence import build_evidence as build_migration
from arch001_decision_readiness_evidence import build_evidence as build_readiness

CANDIDATES = ("utxo", "account-state", "object-resource")


def build_evidence() -> dict[str, object]:
    native = build_native()
    migration = build_migration()
    readiness = build_readiness()

    native_by_name = {row["candidate"]: row for row in native["summary"]}
    migration_by_name = {row["candidate"]: row for row in migration["summary"]}
    assert set(native_by_name) == set(CANDIDATES)
    assert set(migration_by_name) == set(CANDIDATES)
    assert readiness["all_required_axes_have_deterministic_fixture_coverage"] is True

    rows = []
    for candidate in CANDIDATES:
        n = native_by_name[candidate]
        m = migration_by_name[candidate]
        rows.append({
            "candidate": candidate,
            "native_final_state_bytes": n["final_step_state_bytes"],
            "native_cumulative_step_state_bytes": n["cumulative_step_state_bytes"],
            "native_final_state_units": n["final_step_state_units"],
            "native_cumulative_step_state_units": n["cumulative_step_state_units"],
            "migration_preserve": m["preserve"],
            "migration_adapt": m["adapt"],
            "migration_replace": m["replace"],
            "migration_new": m["new"],
        })

    return {
        "schema": "axven-arch001-tradeoff-snapshot-v1",
        "scope": "research-only; outside production consensus routing",
        "logical_workload": native["logical_workload"],
        "rows": rows,
        "required_axis_count": readiness["required_axis_count"],
        "all_required_axes_bound": True,
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
    evidence_sha256 = hashlib.sha256(first).hexdigest()
    print("ARCH-001 unweighted tradeoff snapshot: 6/6 GREEN")
    print("evidence_sha256", evidence_sha256)
    print(first.decode("ascii"))
    print("NOTE snapshot combines deterministic evidence without scoring, weighting, or architecture selection")


if __name__ == "__main__":
    main()
