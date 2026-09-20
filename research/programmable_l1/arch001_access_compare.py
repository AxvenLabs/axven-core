#!/usr/bin/env python3
"""ARCH-001 research-only access/conflict comparison."""
from __future__ import annotations

from arch001_model import ResearchTransaction, access_conflicts, commitment


def tx(sender, seq, read_set, write_set):
    return ResearchTransaction(sender,seq,tuple(read_set),tuple(write_set),"native-transfer",{"amount":1},1000,"ed25519")


def main() -> None:
    alice=tx("alice",0,["balance:alice","balance:bob"],["balance:alice","balance:bob"])
    carol=tx("carol",0,["balance:carol","balance:dave"],["balance:carol","balance:dave"])
    eve=tx("eve",0,["balance:alice"],["balance:alice"])

    # Object/resource-style explicit access sets expose scheduling conflicts
    # before execution. This is a research property, not a production scheduler.
    assert access_conflicts(alice,carol) is False
    assert access_conflicts(alice,eve) is True
    assert access_conflicts(eve,alice) is True

    # Ordering of a disjoint pair is intentionally represented separately: a
    # future executor would need a deterministic merge rule before parallelism.
    batch_a=commitment(sorted([alice.txid(),carol.txid()]))
    batch_b=commitment(sorted([carol.txid(),alice.txid()]))
    assert batch_a == batch_b

    print("ARCH-001 access comparison: 4/4 GREEN")
    print("disjoint_batch_commitment",batch_a)
    print("NOTE production parallel execution is NOT claimed")


if __name__ == "__main__":
    main()
