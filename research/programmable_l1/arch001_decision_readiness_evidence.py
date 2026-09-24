#!/usr/bin/env python3
"""ARCH-001 research-only decision-readiness evidence.

Summarizes whether the required comparison axes are deterministically bound
without scoring candidates or selecting an architecture. This is evidence
plumbing only and is not imported by production consensus routing.
"""
from __future__ import annotations

import hashlib
import json

from arch001_evidence_coverage import build_evidence as build_coverage
from arch001_migration_reuse_summary_evidence import build_evidence as build_migration

REQUIRED_AXES = (
    "native_transfer_replay_conflict_ordering",
    "issued_asset_and_program_state",
    "deterministic_state_commitments",
    "fail_closed_no_partial_mutation",
    "state_growth_and_access_sets",
    "rollback_reorg",
    "pq_hybrid_size_cost_sensitivity",
    "migration_reuse_impact",
)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def build_evidence() -> dict[str, object]:
    coverage = build_coverage()
    migration = build_migration()
    observed_axes = tuple(row["requirement"] for row in coverage["required_axes"])
    assert set(observed_axes) == set(REQUIRED_AXES)
    assert coverage["all_required_axes_bound"] is True
    assert coverage["architecture_selected"] is False
    assert migration["counts_are_unweighted"] is True
    assert migration["architecture_selected"] is False

    return {
        "schema": "axven-arch001-decision-readiness-v1",
        "scope": "research-only; outside production consensus routing",
        "candidates": ["utxo", "account-state", "object-resource"],
        "required_axes": sorted(REQUIRED_AXES),
        "required_axis_count": len(REQUIRED_AXES),
        "all_required_axes_have_deterministic_fixture_coverage": True,
        "migration_reuse_is_unweighted": True,
        "canonical_evidence_ready_for_tradeoff_review": True,
        "remaining_diagnostic_only": ["PQ/hybrid wall-clock verification timing"],
        "production_cost_claim": False,
        "production_pq_scheme_selected": False,
        "architecture_selected": False,
    }


def main() -> None:
    first = canonical_bytes(build_evidence())
    second = canonical_bytes(build_evidence())
    assert first == second
    evidence = json.loads(first.decode("ascii"))
    assert evidence["required_axis_count"] == 8
    assert evidence["architecture_selected"] is False
    print("ARCH-001 decision-readiness evidence: 8/8 axes bound")
    print("evidence_sha256", hashlib.sha256(first).hexdigest())
    print(first.decode("ascii"))
    print("NOTE readiness means evidence coverage is bound; it is not an architecture recommendation")


if __name__ == "__main__":
    main()
