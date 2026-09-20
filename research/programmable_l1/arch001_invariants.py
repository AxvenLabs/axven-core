#!/usr/bin/env python3
"""Executable ARCH-001 research invariants."""

from arch001_model import (
    AxvenObject,
    ResearchTransaction,
    access_conflicts,
    canonical_bytes,
    state_commitment,
)


def main() -> None:
    a = AxvenObject("A", "alice", "balance", 0, {"amount": 100}, "ed25519")
    b = AxvenObject("B", "bob", "balance", 0, {"amount": 50}, "hybrid-v1")
    state1 = {"B": b, "A": a}
    state2 = {"A": a, "B": b}
    assert state_commitment(state1) == state_commitment(state2)

    tx = ResearchTransaction(
        "alice", 0, ("A",), ("A",), "native-transfer",
        {"amount": 1, "to": "bob"}, 1000, "ed25519",
    )
    assert canonical_bytes(tx.canonical()) == canonical_bytes(tx.canonical())
    assert tx.txid() == tx.txid()

    disjoint = ResearchTransaction(
        "carol", 0, ("C",), ("C",), "native-transfer",
        {"amount": 1, "to": "dave"}, 1000, "ed25519",
    )
    conflict = ResearchTransaction(
        "eve", 0, ("A",), ("A",), "native-transfer",
        {"amount": 1, "to": "eve"}, 1000, "ed25519",
    )
    assert access_conflicts(tx, disjoint) is False
    assert access_conflicts(tx, conflict) is True

    print("ARCH-001 research invariants: 4/4 GREEN")


if __name__ == "__main__":
    main()
