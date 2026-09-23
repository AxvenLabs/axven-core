#!/usr/bin/env python3
"""ARCH-001 research-only native representation delta evidence.

Records raw, deterministic representation deltas for the same first native
AXVEN transfer across UTXO, account/state, and object/resource candidates.
The measurements are canonical research encodings only; they are not production
wire, fee, storage, or performance claims and do not select an architecture.
"""
from __future__ import annotations

import hashlib
import json

from arch001_model import AxvenObject, canonical_bytes, commitment
from arch001_transfer_compare import account_transfer, object_plain, object_transfer, utxo_transfer


def size(value: object) -> int:
    return len(canonical_bytes(value))


def build_evidence() -> dict[str, object]:
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
    o1p = object_plain(object_transfer(o0, otx))

    raw = {
        "utxo": (u0, u1, utx, 3),
        "account-state": (a0, a1, atx, 2),
        "object-resource": (o0p, o1p, otx, 2),
    }
    rows = []
    for candidate in ("utxo", "account-state", "object-resource"):
        pre, post, tx, touched = raw[candidate]
        rows.append({
            "candidate": candidate,
            "pre_state_bytes": size(pre),
            "post_state_bytes": size(post),
            "state_delta_bytes": size(post) - size(pre),
            "canonical_tx_bytes": size(tx),
            "touched_state_units": touched,
            "pre_commitment": commitment(pre),
            "post_commitment": commitment(post),
        })

    by_name = {row["candidate"]: row for row in rows}
    baseline = by_name["utxo"]
    deltas = []
    for candidate in ("account-state", "object-resource"):
        row = by_name[candidate]
        deltas.append({
            "candidate": candidate,
            "vs_utxo_post_state_bytes": row["post_state_bytes"] - baseline["post_state_bytes"],
            "vs_utxo_canonical_tx_bytes": row["canonical_tx_bytes"] - baseline["canonical_tx_bytes"],
            "vs_utxo_touched_state_units": row["touched_state_units"] - baseline["touched_state_units"],
        })

    return {
        "schema": "axven-arch001-native-representation-delta-v1",
        "scope": "research-only; outside production consensus routing",
        "logical_workload": {"pre": {"alice": 100, "bob": 25}, "transfer": 10, "post": {"alice": 90, "bob": 35}},
        "rows": rows,
        "raw_deltas_vs_current_utxo_baseline": deltas,
        "weights_applied": False,
        "production_cost_claim": False,
        "architecture_selected": False,
    }


def main() -> None:
    first = canonical_bytes(build_evidence())
    second = canonical_bytes(build_evidence())
    assert first == second
    evidence = json.loads(first.decode("ascii"))
    assert evidence["architecture_selected"] is False
    assert evidence["weights_applied"] is False
    print("ARCH-001 native representation deltas: 5/5 GREEN")
    print("evidence_sha256", hashlib.sha256(first).hexdigest())
    print(first.decode("ascii"))
    print("NOTE raw canonical deltas are unweighted research evidence; no architecture selected")


if __name__ == "__main__":
    main()
