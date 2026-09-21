#!/usr/bin/env python3
"""ARCH-001 research-only same-state contention comparison.

This executable evidence stays outside production consensus routing. It compares
how the UTXO, account/state, and object/resource prototypes fail closed when two
transactions are derived from the same pre-state and both try to spend/mutate
the same sender state.
"""
from __future__ import annotations

from copy import deepcopy

from arch001_model import AxvenObject, canonical_bytes, commitment, state_commitment
from arch001_transfer_compare import account_transfer, object_transfer, utxo_transfer


def rejected(fn) -> str:
    try:
        fn()
    except Exception as exc:  # research harness records the prototype rejection reason
        return str(exc)
    raise AssertionError("conflicting transition accepted")


def run_once():
    # Equivalent pre-state and competing native AXVEN transfers:
    # Alice=100, Bob=25, Carol=5. T1 Alice->Bob 10, T2 Alice->Carol 7.
    u0 = {
        "alice:0": {"owner": "alice", "amount": 100},
        "bob:0": {"owner": "bob", "amount": 25},
        "carol:0": {"owner": "carol", "amount": 5},
    }
    a0 = {
        "alice": {"balance": 100, "sequence": 0},
        "bob": {"balance": 25, "sequence": 0},
        "carol": {"balance": 5, "sequence": 0},
    }
    o0 = {
        "alice": AxvenObject("alice", "alice", "native-balance", 0, {"amount": 100}, "hybrid-v1"),
        "bob": AxvenObject("bob", "bob", "native-balance", 0, {"amount": 25}, "hybrid-v1"),
        "carol": AxvenObject("carol", "carol", "native-balance", 0, {"amount": 5}, "hybrid-v1"),
    }

    u, a, o = deepcopy(u0), deepcopy(a0), deepcopy(o0)
    spent = set()
    pre = {"utxo": commitment(u), "account": commitment(a), "object": state_commitment(o)}

    # Apply T1. T2 was constructed against exactly the same pre-state.
    utxo_transfer(u, spent, "alice:0", "alice", "bob", 10)
    account_transfer(a, "alice", "bob", 10, 0)
    object_transfer(o, "alice", "bob", 10, 0)

    after_t1 = {"utxo": commitment(u), "account": commitment(a), "object": state_commitment(o)}
    snapshot = deepcopy((u, a, o, spent))

    reasons = {
        "utxo": rejected(lambda: utxo_transfer(u, spent, "alice:0", "alice", "carol", 7)),
        "account": rejected(lambda: account_transfer(a, "alice", "carol", 7, 0)),
        "object": rejected(lambda: object_transfer(o, "alice", "carol", 7, 0)),
    }

    # Rejected conflicting T2 must not partially mutate any candidate state.
    assert (u, a, o, spent) == snapshot
    assert sum(x["amount"] for x in u.values()) == 130
    assert sum(x["balance"] for x in a.values()) == 130
    assert sum(x.data["amount"] for x in o.values()) == 130

    final = {"utxo": commitment(u), "account": commitment(a), "object": state_commitment(o)}
    assert final == after_t1

    evidence = {
        "workload": "native-AXVEN-same-sender-contention-v1",
        "pre_commitments": pre,
        "accepted_t1_post_commitments": after_t1,
        "conflicting_t2_rejected": {k: True for k in reasons},
        "rejection_reasons": reasons,
        "rejected_t2_state_unchanged": True,
        "conserved_total": 130,
    }
    return evidence


def main():
    first = run_once()
    second = run_once()
    first_bytes = canonical_bytes(first)
    assert first_bytes == canonical_bytes(second)
    print("ARCH-001 contention evidence: 9/9 GREEN")
    print(first_bytes.decode("ascii"))
    print("NOTE rejection mechanisms differ; this evidence does not select an architecture")


if __name__ == "__main__":
    main()
