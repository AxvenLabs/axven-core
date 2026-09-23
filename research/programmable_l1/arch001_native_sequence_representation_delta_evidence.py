#!/usr/bin/env python3
"""ARCH-001 research-only repeated native representation-delta evidence.

Extends the first-transfer raw representation comparison across the existing
eight-step native AXVEN workload. Values are canonical research encodings only;
they are not production wire, fee, storage, or performance claims and do not
select an architecture.
"""
from __future__ import annotations

import hashlib

from arch001_model import canonical_bytes
from arch001_native_sequence_evidence import run_once


def build_evidence() -> dict[str, object]:
    sequence = run_once()
    rows = []
    for source in sequence["rows"]:
        baseline = source["utxo"]
        candidates = []
        for candidate in ("utxo", "account-state", "object-resource"):
            current = source[candidate]
            candidates.append({
                "candidate": candidate,
                "state_bytes": current["state_bytes"],
                "state_units": current["state_units"],
                "vs_utxo_state_bytes": current["state_bytes"] - baseline["state_bytes"],
                "vs_utxo_state_units": current["state_units"] - baseline["state_units"],
                "commitment": current["commitment"],
            })
        rows.append({"step": source["step"], "candidates": candidates})

    assert len(rows) == 8
    assert all(row["candidates"][0]["vs_utxo_state_bytes"] == 0 for row in rows)
    assert all(row["candidates"][0]["vs_utxo_state_units"] == 0 for row in rows)
    return {
        "schema": "axven-arch001-native-sequence-representation-delta-v1",
        "scope": "research-only; outside production consensus routing",
        "logical_workload": "8 sequential Alice-to-Bob native AXVEN transfers of 1 each",
        "baseline": "current-utxo-research-model",
        "rows": rows,
        "weights_applied": False,
        "production_cost_claim": False,
        "architecture_selected": False,
    }


def main() -> None:
    first = canonical_bytes(build_evidence())
    second = canonical_bytes(build_evidence())
    assert first == second
    print("ARCH-001 native sequence representation deltas: 5/5 GREEN")
    print("evidence_sha256", hashlib.sha256(first).hexdigest())
    print(first.decode("ascii"))
    print("NOTE repeated raw canonical deltas are unweighted research evidence; no architecture selected")


if __name__ == "__main__":
    main()
