#!/usr/bin/env python3
"""ARCH-001 research-only independent native-AXVEN batch ordering evidence.

This executable prototype stays outside production consensus routing. It compares
whether two disjoint native transfers commute under the UTXO, account/state and
Axven object/resource candidates. It deliberately does not select an architecture.
"""
from __future__ import annotations

from arch001_model import AxvenObject, canonical_bytes, commitment
from arch001_transfer_compare import account_transfer, object_plain, object_transfer, utxo_transfer


def roots(u, a, o):
    return {"utxo": commitment(u), "account": commitment(a), "object": commitment(object_plain(o))}


def apply_pair(u0, a0, o0, order):
    ut = {
        "a": {"txid": "a", "input": "alice:0", "sender": "alice", "recipient": "bob", "amount": 10},
        "c": {"txid": "c", "input": "carol:0", "sender": "carol", "recipient": "dave", "amount": 7},
    }
    at = {
        "a": {"sender": "alice", "recipient": "bob", "amount": 10, "sequence": 0},
        "c": {"sender": "carol", "recipient": "dave", "amount": 7, "sequence": 0},
    }
    ot = {
        "a": {"sender": "alice", "source_object": "alice", "destination_object": "bob", "source_version": 0, "destination_version": 0, "amount": 10},
        "c": {"sender": "carol", "source_object": "carol", "destination_object": "dave", "source_version": 0, "destination_version": 0, "amount": 7},
    }
    u, a, o = u0, a0, o0
    for key in order:
        u, a, o = utxo_transfer(u, ut[key]), account_transfer(a, at[key]), object_transfer(o, ot[key])
    return u, a, o


def run_once():
    u0 = {
        "alice:0": {"owner": "alice", "amount": 100}, "bob:0": {"owner": "bob", "amount": 25},
        "carol:0": {"owner": "carol", "amount": 40}, "dave:0": {"owner": "dave", "amount": 5},
    }
    a0 = {name: {"balance": bal, "sequence": 0} for name, bal in (("alice",100),("bob",25),("carol",40),("dave",5))}
    o0 = {name: AxvenObject(name, name, "native-balance", 0, {"amount": bal}, "hybrid-v1") for name, bal in (("alice",100),("bob",25),("carol",40),("dave",5))}

    abc = apply_pair(u0, a0, o0, ("a", "c"))
    cba = apply_pair(u0, a0, o0, ("c", "a"))
    r_ac, r_ca = roots(*abc), roots(*cba)
    assert r_ac == r_ca
    assert sum(x["amount"] for x in abc[0].values()) == 170
    assert sum(x["balance"] for x in abc[1].values()) == 170
    assert sum(x.data["amount"] for x in abc[2].values()) == 170
    return {
        "workload": "native-AXVEN-disjoint-batch-order-v1",
        "pre_commitments": roots(u0, a0, o0),
        "order_ac_post_commitments": r_ac,
        "order_ca_post_commitments": r_ca,
        "order_independent_final_state": {"utxo": True, "account": True, "object": True},
        "conserved_total": 170,
        "scope": "research-only; no production consensus routing",
    }


def main():
    first, second = run_once(), run_once()
    evidence = canonical_bytes(first)
    assert evidence == canonical_bytes(second)
    print("ARCH-001 disjoint batch-order evidence: 8/8 GREEN")
    print(evidence.decode("ascii"))
    print("NOTE all candidates commute for this disjoint workload; no architecture selected")


if __name__ == "__main__":
    main()
