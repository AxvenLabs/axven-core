#!/usr/bin/env python3
"""ARCH-001 research-only native workload equivalence contract.

Proves that the first native AXVEN comparison feeds the three candidate models
the same logical economic workload and normalizes to the same logical result.
This is evidence plumbing only and is not imported by production consensus.
"""
from __future__ import annotations

import hashlib
import json

from arch001_model import AxvenObject, commitment
from arch001_transfer_compare import account_transfer, object_plain, object_transfer, rejected, utxo_transfer


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def logical_balances(name: str, state: object) -> dict[str, int]:
    if name == "utxo":
        balances = {"alice": 0, "bob": 0}
        for coin in state.values():
            balances[coin["owner"]] += coin["amount"]
        return balances
    if name == "account-state":
        return {owner: row["balance"] for owner, row in sorted(state.items())}
    if name == "object-resource":
        return {obj.owner_or_authority: obj.data["amount"] for obj in state.values()}
    raise AssertionError(name)


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
    o1 = object_transfer(o0, otx)
    expected_pre = {"alice": 100, "bob": 25}
    expected_post = {"alice": 90, "bob": 35}
    rows = []
    for name, pre, post, tx, fn in (
        ("utxo", u0, u1, utx, utxo_transfer),
        ("account-state", a0, a1, atx, account_transfer),
        ("object-resource", o0, o1, otx, object_transfer),
    ):
        pre_logical = logical_balances(name, pre)
        post_logical = logical_balances(name, post)
        assert pre_logical == expected_pre
        assert post_logical == expected_post
        assert sum(pre_logical.values()) == sum(post_logical.values()) == 125
        assert rejected(fn, post, tx)
        normalized = object_plain(post) if name == "object-resource" else post
        rows.append({
            "candidate": name,
            "logical_pre": pre_logical,
            "logical_post": post_logical,
            "native_supply": 125,
            "replay_rejected": True,
            "post_commitment": commitment(normalized),
        })
    return {
        "schema": "axven-arch001-native-equivalence-v1",
        "scope": "research-only; outside production consensus routing",
        "logical_workload": {"sender": "alice", "recipient": "bob", "amount": 10, "pre": expected_pre, "post": expected_post},
        "candidates": rows,
        "equivalent_logical_result": True,
        "architecture_selected": False,
    }


def main() -> None:
    first = canonical_bytes(build_evidence())
    second = canonical_bytes(build_evidence())
    assert first == second
    print("ARCH-001 native workload equivalence: 3/3 GREEN")
    print("evidence_sha256", hashlib.sha256(first).hexdigest())
    print(first.decode("ascii"))
    print("NOTE equal logical workload/result does not imply equal representation cost and does not select an architecture")


if __name__ == "__main__":
    main()
