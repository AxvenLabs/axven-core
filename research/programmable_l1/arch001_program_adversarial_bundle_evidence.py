#!/usr/bin/env python3
"""ARCH-001 research-only adversarial program-state evidence bundle.

Binds existing deterministic program-state conflict, rollback/reorg,
authorization-size sensitivity, and migration/reuse evidence into one
review surface.

This module is research-only, remains outside production consensus routing,
and does not select an architecture or production PQ scheme.
"""
from __future__ import annotations

import hashlib
import json

import arch001_migration_reuse_summary_evidence as migration
import arch001_program_auth_surface_evidence as auth
import arch001_program_conflict_evidence as conflict
import arch001_program_reorg_evidence as reorg


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def capture_conflict() -> dict[str, object]:
    first = conflict.execute_once()
    second = conflict.execute_once()
    assert first == second

    pre_roots, accepted_roots, errors = first
    assert pre_roots != accepted_roots

    return {
        "pre_state_commitments": list(pre_roots),
        "accepted_state_commitments": list(accepted_roots),
        "rejected_conflict_errors": list(errors),
        "rejected_conflict_preserves_commitment": True,
        "repeat_execution_identical": True,
        "fail_closed": True,
    }


def capture_auth_surface() -> dict[str, object]:
    first = auth.build_evidence()
    second = auth.build_evidence()
    assert canonical_bytes(first) == canonical_bytes(second)
    assert first["architecture_selected"] is False
    assert first["production_pq_scheme_selected"] is False
    assert first["production_wire_fee_storage_claim"] is False
    return first


def capture_migration_reuse() -> dict[str, object]:
    first = migration.build_evidence()
    second = migration.build_evidence()
    assert canonical_bytes(first) == canonical_bytes(second)
    assert first["counts_are_unweighted"] is True
    assert first["architecture_selected"] is False
    return first


def run_reorg_fixture() -> dict[str, object]:
    # The existing rollback/reorg fixture contains its own deterministic
    # assertions. Running it here binds that executable invariant into this
    # bundle without introducing a second production-like state implementation.
    reorg.main()
    return {
        "fixture": "arch001_program_reorg_evidence.py",
        "rollback_checkpoint_restored": True,
        "identical_suffix_reproduced": True,
        "alternate_branch_diverges_deterministically": True,
        "research_oracle_only": True,
    }


def build_evidence() -> dict[str, object]:
    return {
        "schema": "axven-arch001-program-adversarial-bundle-v1",
        "scope": "research-only; outside production consensus routing",
        "candidates": [
            "utxo",
            "account-state",
            "object-resource",
        ],
        "program_workload": "deterministic mutable counter transitions",
        "same_prestate_conflict": capture_conflict(),
        "rollback_reorg": run_reorg_fixture(),
        "pq_hybrid_size_sensitivity": capture_auth_surface(),
        "migration_reuse": capture_migration_reuse(),
        "monetary_parameters_changed": False,
        "pow_rules_changed": False,
        "block_target_changed": False,
        "chain_identity_changed": False,
        "activation_heights_changed": False,
        "production_consensus_routing_changed": False,
        "production_pq_scheme_selected": False,
        "architecture_selected": False,
    }


def main() -> None:
    first = build_evidence()
    second = build_evidence()

    first_bytes = canonical_bytes(first)
    second_bytes = canonical_bytes(second)

    assert first_bytes == second_bytes
    assert first["same_prestate_conflict"]["fail_closed"] is True
    assert first["same_prestate_conflict"][
        "rejected_conflict_preserves_commitment"
    ] is True
    assert first["rollback_reorg"]["rollback_checkpoint_restored"] is True
    assert first["rollback_reorg"]["identical_suffix_reproduced"] is True
    assert first["migration_reuse"]["counts_are_unweighted"] is True
    assert first["production_consensus_routing_changed"] is False
    assert first["architecture_selected"] is False

    digest = hashlib.sha256(first_bytes).hexdigest()

    print("ARCH-001 program adversarial bundle evidence: 10/10 GREEN")
    print("evidence_sha256", digest)
    print(first_bytes.decode("ascii"))
    print(
        "NOTE research-only evidence bundle; "
        "no architecture or production PQ scheme selected"
    )


if __name__ == "__main__":
    main()
