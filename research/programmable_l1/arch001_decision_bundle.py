#!/usr/bin/env python3
"""ARCH-001 research-only canonical decision-evidence bundle.

Runs the deterministic, architecture-comparative fixtures from the current
research tree and records both source and stdout digests in one canonical
manifest. Diagnostic timing evidence is deliberately excluded because
wall-clock timing is not byte-deterministic. No production consensus module
imports this file.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent

# Only deterministic fixtures belong in the canonical bundle. Authorization
# timing sensitivity remains a separate diagnostic artifact; deterministic
# classical/PQ/hybrid witness-size sensitivity is included.
FIXTURES = (
    "arch001_invariants.py",
    "arch001_transfer_compare.py",
    "arch001_native_equivalence_evidence.py",
    "arch001_native_representation_delta_evidence.py",
    "arch001_native_sequence_representation_delta_evidence.py",
    "arch001_native_sequence_summary_evidence.py",
    "arch001_native_marginal_growth_evidence.py",
    "arch001_token_compare.py",
    "arch001_token_program_compare.py",
    "arch001_program_conflict_evidence.py",
    "arch001_program_reorg_evidence.py",
    "arch001_program_sequence_evidence.py",
    "arch001_program_auth_surface_evidence.py",
    "arch001_contention_compare.py",
    "arch001_batch_order_compare.py",
    "arch001_access_compare.py",
    "arch001_state_growth_compare.py",
    "arch001_rollback_compare.py",
    "arch001_migration_reuse_compare.py",
    "arch001_migration_reuse_summary_evidence.py",
    "arch001_auth_size_evidence.py",
    "arch001_native_measurement_evidence.py",
    "arch001_native_sequence_evidence.py",
    "arch001_native_auth_surface_evidence.py",
    "arch001_native_reorg_sequence_evidence.py",
    "arch001_evidence_coverage.py",
    "arch001_decision_readiness_evidence.py",
    "arch001_tradeoff_snapshot_evidence.py",
)


def canonical_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def run_fixture(name: str) -> dict[str, object]:
    path = ROOT / name
    source = path.read_bytes()
    proc = subprocess.run(
        [sys.executable, str(path)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )
    stdout = proc.stdout
    stderr = proc.stderr
    return {
        "fixture": name,
        "source_bytes": len(source),
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "exit_code": proc.returncode,
        "stdout_bytes": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_bytes": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }


def build_bundle() -> dict[str, object]:
    rows = [run_fixture(name) for name in FIXTURES]
    assert len(rows) == len(FIXTURES)
    assert all(row["exit_code"] == 0 for row in rows)
    assert all(row["stderr_bytes"] == 0 for row in rows)
    assert all(row["source_bytes"] > 0 for row in rows)
    return {
        "schema": "axven-arch001-decision-evidence-v2",
        "scope": "research-only; outside production consensus routing",
        "candidates": ["utxo", "account-state", "object-resource"],
        "fixture_count": len(rows),
        "fixtures": rows,
        "fixture_source_provenance_included": True,
        "required_evidence_coverage_bound": True,
        "native_workload_equivalence_bound": True,
        "native_representation_deltas_bound": True,
        "native_sequence_representation_deltas_bound": True,
        "native_sequence_summary_bound": True,
        "native_marginal_growth_bound": True,
        "migration_reuse_summary_bound": True,
        "decision_readiness_bound": True,
        "tradeoff_snapshot_bound": True,
        "excluded_nondeterministic_diagnostics": ["arch001_auth_cost_compare.py:median_verify_ns"],
        "architecture_selected": False,
    }


def main() -> None:
    first = build_bundle()
    second = build_bundle()
    first_bytes = canonical_bytes(first)
    second_bytes = canonical_bytes(second)
    assert first_bytes == second_bytes
    assert first["fixture_count"] == len(first["fixtures"]) == len(FIXTURES)
    digest = hashlib.sha256(first_bytes).hexdigest()
    fixture_count = first["fixture_count"]
    print(f"ARCH-001 canonical decision bundle: {fixture_count}/{fixture_count} GREEN")
    print("bundle_sha256", digest)
    print(first_bytes.decode("ascii"))
    print("NOTE fixture sources, outputs, required evidence coverage, native workload equivalence, raw representation deltas, native sequence summary, marginal growth, migration/reuse summary, decision readiness, and unweighted tradeoff snapshot are digest-bound; PQ/hybrid timing remains diagnostic; no architecture selected")


if __name__ == "__main__":
    main()
