#!/usr/bin/env python3
"""ARCH-001 research-only decision-evidence coverage gate.

Binds every required decision-workload axis to explicit deterministic fixtures.
This does not score candidates or select an architecture and is not imported by
production consensus routing.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

REQUIRED = {
    "native_transfer_replay_conflict_ordering": (
        "arch001_transfer_compare.py",
        "arch001_contention_compare.py",
        "arch001_batch_order_compare.py",
    ),
    "issued_asset_and_program_state": (
        "arch001_token_compare.py",
        "arch001_token_program_compare.py",
        "arch001_program_conflict_evidence.py",
        "arch001_program_sequence_evidence.py",
    ),
    "deterministic_state_commitments": (
        "arch001_invariants.py",
        "arch001_native_measurement_evidence.py",
    ),
    "fail_closed_no_partial_mutation": (
        "arch001_transfer_compare.py",
        "arch001_program_conflict_evidence.py",
        "arch001_native_measurement_evidence.py",
    ),
    "state_growth_and_access_sets": (
        "arch001_access_compare.py",
        "arch001_state_growth_compare.py",
        "arch001_native_sequence_evidence.py",
        "arch001_program_sequence_evidence.py",
    ),
    "rollback_reorg": (
        "arch001_rollback_compare.py",
        "arch001_native_reorg_sequence_evidence.py",
        "arch001_program_reorg_evidence.py",
    ),
    "pq_hybrid_size_cost_sensitivity": (
        "arch001_auth_size_evidence.py",
        "arch001_native_auth_surface_evidence.py",
        "arch001_program_auth_surface_evidence.py",
    ),
    "migration_reuse_impact": (
        "arch001_migration_reuse_compare.py",
    ),
}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def build_evidence() -> dict[str, object]:
    rows = []
    for requirement, fixtures in sorted(REQUIRED.items()):
        bound = []
        for name in fixtures:
            data = (ROOT / name).read_bytes()
            assert data
            bound.append({"fixture": name, "source_bytes": len(data), "source_sha256": hashlib.sha256(data).hexdigest()})
        rows.append({"requirement": requirement, "fixtures": bound})

    assert len(rows) == 8
    assert all(row["fixtures"] for row in rows)
    return {
        "schema": "axven-arch001-evidence-coverage-v1",
        "scope": "research-only; outside production consensus routing",
        "candidates": ["utxo", "account-state", "object-resource"],
        "required_axes": rows,
        "required_axis_count": 8,
        "all_required_axes_bound": True,
        "architecture_selected": False,
    }


def main() -> None:
    first = canonical_bytes(build_evidence())
    second = canonical_bytes(build_evidence())
    assert first == second
    print("ARCH-001 evidence coverage gate: 8/8 GREEN")
    print("evidence_sha256", hashlib.sha256(first).hexdigest())
    print(first.decode("ascii"))
    print("NOTE coverage is provenance-bound research evidence; no architecture selected")


if __name__ == "__main__":
    main()
