#!/usr/bin/env python3
"""ARCH-001 research-only same-state contention comparison.

No production consensus module imports this file. Two native-AXVEN transfers are
constructed from the same pre-state; after T1 is accepted, stale T2 must reject
fail-closed without partial mutation in every candidate model.
"""
from __future__ import annotations

from arch001_model import AxvenObject, ResearchTransitionError, canonical_bytes, commitment
from arch001_transfer_compare import account_transfer, object_plain, object_transfer, utxo_transfer


def reject_reason(fn) -> str:
    try:
        fn()
    except ResearchTransitionError as exc:
        return str(exc)
    raise AssertionError("conflicting transition accepted")


def roots(u, a, o):
    return {"utxo": commitment(u), "account": commitment(a), "object": commitment(object_plain(o))}


def run_once():
    # Equivalent pre-state: Alice=100, Bob=25, Carol=5 AXVEN.
    u0 = {"alice:0": {"owner": "alice", "amount": 100},
          "bob:0": {"owner": "bob", "amount": 25},
          "carol:0": {"owner": "carol", "amount": 5}}
    a0 = {"alice": {"balance": 100, "sequence": 0},
          "bob": {"balance": 25, "sequence": 0},
          "carol": {"balance": 5, "sequence": 0}}
    o0 = {
        "alice": AxvenObject("alice", "alice", "native-balance", 0, {"amount": 100}, "hybrid-v1"),
        "bob": AxvenObject("bob", "bob", "native-balance", 0, {"amount": 25}, "hybrid-v1"),
        "carol": AxvenObject("carol", "carol", "native-balance", 0, {"amount": 5}, "hybrid-v1"),
    }

    # T1 Alice->Bob 10; competing T2 Alice->Carol 7, both built at pre-state.
    ut1 = {"txid": "t1", "input": "alice:0", "sender": "alice", "recipient": "bob", "amount": 10}
    ut2 = {"txid": "t2", "input": "alice:0", "sender": "alice", "recipient": "carol", "amount": 7}
    at1 = {"sender": "alice", "recipient": "bob", "amount": 10, "sequence": 0}
    at2 = {"sender": "alice", "recipient": "carol", "amount": 7, "sequence": 0}
    ot1 = {"sender": "alice", "source_object": "alice", "destination_object": "bob",
           "source_version": 0, "destination_version": 0, "amount": 10}
    ot2 = {"sender": "alice", "source_object": "alice", "destination_object": "carol",
           "source_version": 0, "destination_version": 0, "amount": 7}

    pre = roots(u0, a0, o0)
    u1, a1, o1 = utxo_transfer(u0, ut1), account_transfer(a0, at1), object_transfer(o0, ot1)
    post = roots(u1, a1, o1)

    reasons = {
        "utxo": reject_reason(lambda: utxo_transfer(u1, ut2)),
        "account": reject_reason(lambda: account_transfer(a1, at2)),
        "object": reject_reason(lambda: object_transfer(o1, ot2)),
    }

    # Prototype transitions return fresh state; rejection therefore cannot partially mutate accepted T1 state.
    assert roots(u1, a1, o1) == post
    assert sum(x["amount"] for x in u1.values()) == 130
    assert sum(x["balance"] for x in a1.values()) == 130
    assert sum(x.data["amount"] for x in o1.values()) == 130

    return {
        "workload": "native-AXVEN-same-sender-contention-v1",
        "pre_commitments": pre,
        "accepted_t1_post_commitments": post,
        "conflicting_t2_rejected": {"utxo": True, "account": True, "object": True},
        "rejection_reasons": reasons,
        "rejected_t2_state_unchanged": True,
        "conserved_total": 130,
    }


def main():
    first, second = run_once(), run_once()
    evidence = canonical_bytes(first)
    assert evidence == canonical_bytes(second)
    assert first["rejection_reasons"] == {
        "utxo": "missing/spent input",
        "account": "stale account sequence",
        "object": "stale object version",
    }
    print("ARCH-001 contention evidence: 10/10 GREEN")
    print(evidence.decode("ascii"))
    print("NOTE rejection mechanisms differ; this evidence does not select an architecture")


if __name__ == "__main__":
    main()
