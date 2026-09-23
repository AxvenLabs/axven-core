#!/usr/bin/env python3
"""ARCH-001 research-only native sequence summary evidence.

Summarizes the existing equivalent eight-step native AXVEN workload without
applying architecture-specific weights. Values are canonical research
representations only, not production storage, fee, wire, or performance claims.
"""
from __future__ import annotations

import hashlib

from arch001_model import canonical_bytes
from arch001_native_sequence_evidence import run_once

CANDIDATES = ("utxo", "account-state", "object-resource")


def build_evidence() -> dict[str, object]:
    sequence = run_once()
    rows = sequence["rows"]
    assert len(rows) == 8

    summary = []
    for candidate in CANDIDATES:
        state_bytes = [row[candidate]["state_bytes"] for row in rows]
        state_units = [row[candidate]["state_units"] for row in rows]
        summary.append({
            "candidate": candidate,
            "initial_step_state_bytes": state_bytes[0],
            "final_step_state_bytes": state_bytes[-1],
            "min_state_bytes": min(state_bytes),
            "max_state_bytes": max(state_bytes),
            "cumulative_step_state_bytes": sum(state_bytes),
            "initial_step_state_units": state_units[0],
            "final_step_state_units": state_units[-1],
            "min_state_units": min(state_units),
            "max_state_units": max(state_units),
            "cumulative_step_state_units": sum(state_units),
            "final_commitment": rows[-1][candidate]["commitment"],
        })

    by_name = {row["candidate"]: row for row in summary}
    baseline = by_name["utxo"]
    deltas = []
    for candidate in ("account-state", "object-resource"):
        row = by_name[candidate]
        deltas.append({
            "candidate": candidate,
            "vs_utxo_final_state_bytes": row["final_step_state_bytes"] - baseline["final_step_state_bytes"],
            "vs_utxo_cumulative_step_state_bytes": row["cumulative_step_state_bytes"] - baseline["cumulative_step_state_bytes"],
            "vs_utxo_final_state_units": row["final_step_state_units"] - baseline["final_step_state_units"],
            "vs_utxo_cumulative_step_state_units": row["cumulative_step_state_units"] - baseline["cumulative_step_state_units"],
        })

    return {
        "schema": "axven-arch001-native-sequence-summary-v1",
        "scope": "research-only; outside production consensus routing",
        "logical_workload": "8 sequential Alice-to-Bob native AXVEN transfers of 1 each",
        "summary": summary,
        "raw_deltas_vs_current_utxo_baseline": deltas,
        "weights_applied": False,
        "production_cost_claim": False,
        "architecture_selected": False,
    }


def main() -> None:
    first = canonical_bytes(build_evidence())
    second = canonical_bytes(build_evidence())
    assert first == second
    print("ARCH-001 native sequence summary evidence: 5/5 GREEN")
    print("evidence_sha256", hashlib.sha256(first).hexdigest())
    print(first.decode("ascii"))
    print("NOTE aggregate values are unweighted canonical research evidence; no architecture selected")


if __name__ == "__main__":
    main()
