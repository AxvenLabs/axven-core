#!/usr/bin/env python3
"""ARCH-001 research-only canonical native-transfer measurement evidence.

Records directly comparable deterministic measurements for the same logical
native AXVEN transfer across the UTXO baseline, account/state prototype, and
object/resource prototype. This is diagnostic research evidence only and is
not imported by production consensus.
"""
from __future__ import annotations

import json

from arch001_model import canonical_bytes, commitment
from arch001_transfer_compare import (
    AxvenObject,
    account_transfer,
    object_plain,
    object_transfer,
    utxo_transfer,
)


def size(value) -> int:
    return len(canonical_bytes(value))


def rejected_unchanged(apply, accepted, stale_tx) -> tuple[bool, bool]:
    before = commitment(accepted)
    try:
        apply(accepted, stale_tx)
    except (AssertionError, KeyError, ValueError):
        return True, commitment(accepted) == before
    return False, False


def main() -> None:
    u0 = {"genesis:0": {"owner": "alice", "amount": 100}, "genesis:1": {"owner": "bob", "amount": 25}}
    utx = {"txid": "transfer1", "input": "genesis:0", "sender": "alice", "recipient": "bob", "amount": 10}
    a0 = {"alice": {"balance": 100, "sequence": 0}, "bob": {"balance": 25, "sequence": 0}}
    atx = {"sender": "alice", "recipient": "bob", "amount": 10, "sequence": 0}
    o0 = {
        "alice-balance": AxvenObject("alice-balance", "alice", "native-balance", 0, {"amount": 100}, "ed25519"),
        "bob-balance": AxvenObject("bob-balance", "bob", "native-balance", 0, {"amount": 25}, "hybrid-v1"),
    }
    otx = {"sender": "alice", "source_object": "alice-balance", "destination_object": "bob-balance", "source_version": 0, "destination_version": 0, "amount": 10}

    u1 = utxo_transfer(u0, utx)
    a1 = account_transfer(a0, atx)
    o0p = object_plain(o0)
    o1 = object_transfer(o0, otx)
    o1p = object_plain(o1)

    ur, uu = rejected_unchanged(utxo_transfer, u1, utx)
    ar, au = rejected_unchanged(account_transfer, a1, atx)
    before_o = commitment(o1p)
    try:
        object_transfer(o1, otx)
        orj, ou = False, False
    except (AssertionError, KeyError, ValueError):
        orj, ou = True, commitment(object_plain(o1)) == before_o

    rows = []
    for name, pre, post, tx, touched, replay_rejected, unchanged in (
        ("utxo", u0, u1, utx, 3, ur, uu),
        ("account-state", a0, a1, atx, 2, ar, au),
        ("object-resource", o0p, o1p, otx, 2, orj, ou),
    ):
        rows.append({
            "candidate": name,
            "pre_state_bytes": size(pre),
            "post_state_bytes": size(post),
            "state_delta_bytes": size(post) - size(pre),
            "canonical_tx_bytes": size(tx),
            "touched_state_units": touched,
            "pre_commitment": commitment(pre),
            "post_commitment": commitment(post),
            "replay_rejected": replay_rejected,
            "rejected_state_unchanged": unchanged,
        })

    assert all(r["replay_rejected"] and r["rejected_state_unchanged"] for r in rows)
    assert sum(v["amount"] for v in u1.values()) == 125
    assert sum(v["balance"] for v in a1.values()) == 125
    assert sum(v["payload"]["amount"] for v in o1p.values()) == 125

    evidence = {
        "schema": "axven-arch001-native-measurement-v1",
        "scope": "research-only; outside production consensus routing",
        "logical_workload": {"initial_total": 125, "sender": "alice", "recipient": "bob", "amount": 10},
        "rows": rows,
        "production_cost_claim": False,
        "architecture_selected": False,
    }
    encoded = canonical_bytes(evidence)
    assert encoded == canonical_bytes(json.loads(encoded.decode("ascii")))
    print("ARCH-001 canonical native measurement evidence: 8/8 GREEN")
    print(encoded.decode("ascii"))


if __name__ == "__main__":
    main()
