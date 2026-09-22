#!/usr/bin/env python3
"""ARCH-001 research-only repeated native-transfer measurement evidence.

Runs the same deterministic native AXVEN transfer sequence across the UTXO,
account/state, and object/resource candidates. This is diagnostic architecture
research only and is not imported by production consensus.
"""
from __future__ import annotations

from arch001_model import AxvenObject, canonical_bytes, commitment
from arch001_transfer_compare import account_transfer, object_plain, object_transfer, utxo_transfer


def size(value) -> int:
    return len(canonical_bytes(value))


def run_once() -> dict[str, object]:
    u = {"genesis:0": {"owner": "alice", "amount": 100}, "genesis:1": {"owner": "bob", "amount": 25}}
    a = {"alice": {"balance": 100, "sequence": 0}, "bob": {"balance": 25, "sequence": 0}}
    o = {
        "alice-balance": AxvenObject("alice-balance", "alice", "native-balance", 0, {"amount": 100}, "hybrid-v1"),
        "bob-balance": AxvenObject("bob-balance", "bob", "native-balance", 0, {"amount": 25}, "hybrid-v1"),
    }
    rows = []
    input_id = "genesis:0"
    for i in range(1, 9):
        amount = 1
        utx = {"txid": f"transfer{i}", "input": input_id, "sender": "alice", "recipient": "bob", "amount": amount}
        atx = {"sender": "alice", "recipient": "bob", "amount": amount, "sequence": i - 1}
        otx = {"sender": "alice", "source_object": "alice-balance", "destination_object": "bob-balance", "source_version": i - 1, "destination_version": i - 1, "amount": amount}
        u = utxo_transfer(u, utx)
        a = account_transfer(a, atx)
        o = object_transfer(o, otx)
        input_id = f"transfer{i}:1"
        op = object_plain(o)
        assert sum(x["amount"] for x in u.values()) == 125
        assert sum(x["balance"] for x in a.values()) == 125
        assert sum(x["data"]["amount"] for x in op.values()) == 125
        rows.append({
            "step": i,
            "utxo": {"state_bytes": size(u), "state_units": len(u), "commitment": commitment(u)},
            "account-state": {"state_bytes": size(a), "state_units": len(a), "commitment": commitment(a)},
            "object-resource": {"state_bytes": size(op), "state_units": len(op), "commitment": commitment(op)},
        })
    return {
        "schema": "axven-arch001-native-sequence-v1",
        "scope": "research-only; outside production consensus routing",
        "logical_workload": "8 sequential Alice-to-Bob native AXVEN transfers of 1 each",
        "rows": rows,
        "production_storage_or_fee_claim": False,
        "architecture_selected": False,
    }


def main() -> None:
    first = run_once()
    second = run_once()
    encoded = canonical_bytes(first)
    assert encoded == canonical_bytes(second)
    assert first["rows"][-1]["utxo"]["state_units"] == 10
    assert first["rows"][-1]["account-state"]["state_units"] == 2
    assert first["rows"][-1]["object-resource"]["state_units"] == 2
    print("ARCH-001 repeated native-transfer evidence: 7/7 GREEN")
    print(encoded.decode("ascii"))
    print("NOTE canonical research bytes/state units are not production storage, fee, or architecture scores")


if __name__ == "__main__":
    main()
