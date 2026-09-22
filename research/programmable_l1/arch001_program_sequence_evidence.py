#!/usr/bin/env python3
"""ARCH-001 research-only repeated mutable program-state evidence.

Runs the same eight counter increments through the UTXO baseline, account/state
prototype, and object/resource prototype. Canonical byte counts are research
representation measurements only; they are not production storage/fee claims.
"""
from __future__ import annotations

from arch001_model import AxvenObject, canonical_bytes, commitment, state_commitment
from arch001_token_program_compare import (
    account_program_increment,
    object_program_increment,
    utxo_program_increment,
)


def object_bytes(state):
    return canonical_bytes({k: state[k].canonical() for k in sorted(state)})


def run_once():
    u = {"counter:0": {"owner": "program:counter", "asset": "STATE", "amount": 7}}
    a = {"program:counter": {"counter": 7, "sequence": 0}}
    o = {"counter": AxvenObject("counter", "program:counter", "counter", 0, {"value": 7}, "program-policy")}
    spent = set()
    rows = []

    for step in range(1, 9):
        old = f"counter:{step - 1}"
        new = f"counter:{step}"
        utxo_program_increment(u, spent, old, new)
        account_program_increment(a, "program:counter", step - 1)
        object_program_increment(o, "counter", step - 1)

        value = 7 + step
        assert u[new]["amount"] == a["program:counter"]["counter"] == o["counter"].data["value"] == value
        ub = canonical_bytes(u)
        ab = canonical_bytes(a)
        ob = object_bytes(o)
        rows.append({
            "step": step,
            "counter": value,
            "utxo": {"state_bytes": len(ub), "state_units": len(u), "commitment": commitment(u)},
            "account-state": {"state_bytes": len(ab), "state_units": len(a), "commitment": commitment(a)},
            "object-resource": {"state_bytes": len(ob), "state_units": len(o), "commitment": state_commitment(o)},
        })

    return {
        "schema": "axven-arch001-program-sequence-v1",
        "scope": "research-only; outside production consensus routing",
        "workload": "eight sequential counter increments from 7 to 15",
        "rows": rows,
        "architecture_selected": False,
    }


def main():
    first = run_once()
    second = run_once()
    first_bytes = canonical_bytes(first)
    second_bytes = canonical_bytes(second)
    assert first_bytes == second_bytes
    assert first["rows"][-1]["counter"] == 15
    print("ARCH-001 repeated program-state evidence: 4/4 GREEN")
    print("evidence_sha256", commitment(first))
    print(first_bytes.decode("ascii"))
    print("NOTE byte/state-unit counts are research representations; no architecture selected")


if __name__ == "__main__":
    main()
