#!/usr/bin/env python3
"""ARCH-001 research-only marginal native-state growth evidence.

Derives per-step canonical state growth from the existing equivalent eight-step
native AXVEN workload. Values are representation diagnostics only and are not
production storage, fee, wire, or performance claims.
"""
from __future__ import annotations

import hashlib

from arch001_model import canonical_bytes
from arch001_native_sequence_evidence import run_once

CANDIDATES = ("utxo", "account-state", "object-resource")


def build_evidence() -> dict[str, object]:
    rows = run_once()["rows"]
    assert len(rows) == 8
    candidates = []
    for candidate in CANDIDATES:
        byte_series = [row[candidate]["state_bytes"] for row in rows]
        unit_series = [row[candidate]["state_units"] for row in rows]
        byte_deltas = [byte_series[i] - byte_series[i - 1] for i in range(1, len(byte_series))]
        unit_deltas = [unit_series[i] - unit_series[i - 1] for i in range(1, len(unit_series))]
        candidates.append({
            "candidate": candidate,
            "state_bytes_by_step": byte_series,
            "state_units_by_step": unit_series,
            "marginal_state_bytes_after_first_step": byte_deltas,
            "marginal_state_units_after_first_step": unit_deltas,
            "net_state_bytes_step1_to_step8": byte_series[-1] - byte_series[0],
            "net_state_units_step1_to_step8": unit_series[-1] - unit_series[0],
            "monotonic_non_decreasing_state_bytes": all(b >= a for a, b in zip(byte_series, byte_series[1:])),
            "monotonic_non_decreasing_state_units": all(b >= a for a, b in zip(unit_series, unit_series[1:])),
        })
    by_name = {row["candidate"]: row for row in candidates}
    assert by_name["utxo"]["net_state_units_step1_to_step8"] == 7
    assert by_name["account-state"]["net_state_units_step1_to_step8"] == 0
    assert by_name["object-resource"]["net_state_units_step1_to_step8"] == 0
    return {
        "schema": "axven-arch001-native-marginal-growth-v1",
        "scope": "research-only; outside production consensus routing",
        "logical_workload": "8 sequential Alice-to-Bob native AXVEN transfers of 1 each",
        "candidates": candidates,
        "weights_applied": False,
        "production_cost_claim": False,
        "architecture_selected": False,
    }


def main() -> None:
    first = canonical_bytes(build_evidence())
    second = canonical_bytes(build_evidence())
    assert first == second
    print("ARCH-001 native marginal growth evidence: 6/6 GREEN")
    print("evidence_sha256", hashlib.sha256(first).hexdigest())
    print(first.decode("ascii"))
    print("NOTE marginal growth is unweighted canonical research evidence; no architecture selected")


if __name__ == "__main__":
    main()
