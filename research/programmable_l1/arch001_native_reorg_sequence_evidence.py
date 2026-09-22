#!/usr/bin/env python3
"""ARCH-001 research-only multi-step native-transfer rollback/reorg evidence.

Extends the equivalent native AXVEN workload across the UTXO, account/state,
and object/resource candidates. It proves deterministic restoration to an
intermediate committed state and deterministic divergence for an alternate
branch. This is research-only and is not imported by production consensus.
"""
from __future__ import annotations

from copy import deepcopy

from arch001_model import AxvenObject, canonical_bytes, commitment
from arch001_transfer_compare import account_transfer, object_plain, object_transfer, utxo_transfer


def roots(u, a, o) -> dict[str, str]:
    return {
        "utxo": commitment(u),
        "account-state": commitment(a),
        "object-resource": commitment(object_plain(o)),
    }


def totals(u, a, o) -> tuple[int, int, int]:
    return (
        sum(x["amount"] for x in u.values()),
        sum(x["balance"] for x in a.values()),
        sum(x.data["amount"] for x in o.values()),
    )


def apply_step(u, a, o, *, step: int, amount: int, input_id: str, branch: str):
    txid = f"{branch}-transfer{step}"
    u = utxo_transfer(u, {
        "txid": txid, "input": input_id, "sender": "alice", "recipient": "bob", "amount": amount,
    })
    a = account_transfer(a, {
        "sender": "alice", "recipient": "bob", "amount": amount, "sequence": step - 1,
    })
    o = object_transfer(o, {
        "sender": "alice", "source_object": "alice-balance", "destination_object": "bob-balance",
        "source_version": step - 1, "destination_version": step - 1, "amount": amount,
    })
    assert totals(u, a, o) == (125, 125, 125)
    return u, a, o, f"{txid}:1"


def run_once() -> dict[str, object]:
    u = {"genesis:0": {"owner": "alice", "amount": 100}, "genesis:1": {"owner": "bob", "amount": 25}}
    a = {"alice": {"balance": 100, "sequence": 0}, "bob": {"balance": 25, "sequence": 0}}
    o = {
        "alice-balance": AxvenObject("alice-balance", "alice", "native-balance", 0, {"amount": 100}, "hybrid-v1"),
        "bob-balance": AxvenObject("bob-balance", "bob", "native-balance", 0, {"amount": 25}, "hybrid-v1"),
    }

    input_id = "genesis:0"
    checkpoint = None
    checkpoint_input = None
    for step in range(1, 9):
        u, a, o, input_id = apply_step(u, a, o, step=step, amount=1, input_id=input_id, branch="main")
        if step == 4:
            checkpoint = (deepcopy(u), deepcopy(a), deepcopy(o))
            checkpoint_input = input_id

    assert checkpoint is not None and checkpoint_input is not None
    main_tip = roots(u, a, o)
    checkpoint_roots = roots(*checkpoint)

    # Research rollback: restore the exact captured step-4 state. This does not
    # prescribe a production undo-log or storage mechanism.
    ur, ar, or_ = deepcopy(checkpoint[0]), deepcopy(checkpoint[1]), deepcopy(checkpoint[2])
    assert roots(ur, ar, or_) == checkpoint_roots

    # Re-apply the original suffix from the same committed checkpoint.
    replay_input = checkpoint_input
    for step in range(5, 9):
        ur, ar, or_, replay_input = apply_step(
            ur, ar, or_, step=step, amount=1, input_id=replay_input, branch="main"
        )
    assert roots(ur, ar, or_) == main_tip

    # Alternate branch from the same step-4 commitment. The first alternate
    # transfer changes amount and txid; all candidates must deterministically
    # produce a different tip while preserving native supply.
    uc, ac, oc = deepcopy(checkpoint[0]), deepcopy(checkpoint[1]), deepcopy(checkpoint[2])
    alt_input = checkpoint_input
    for step, amount in ((5, 2), (6, 1), (7, 1), (8, 1)):
        uc, ac, oc, alt_input = apply_step(
            uc, ac, oc, step=step, amount=amount, input_id=alt_input, branch="alternate"
        )
    alternate_tip = roots(uc, ac, oc)
    assert all(alternate_tip[name] != main_tip[name] for name in main_tip)

    return {
        "schema": "axven-arch001-native-reorg-sequence-v1",
        "scope": "research-only; outside production consensus routing",
        "checkpoint_step": 4,
        "checkpoint_roots": checkpoint_roots,
        "main_tip_roots": main_tip,
        "alternate_tip_roots": alternate_tip,
        "restored_checkpoint_exactly": True,
        "original_suffix_reproduced_exactly": True,
        "alternate_branch_diverged": True,
        "native_supply_preserved": True,
        "production_undo_storage_selected": False,
        "architecture_selected": False,
    }


def main() -> None:
    first = run_once()
    second = run_once()
    encoded = canonical_bytes(first)
    assert encoded == canonical_bytes(second)
    print("ARCH-001 native sequence rollback/reorg evidence: 8/8 GREEN")
    print(encoded.decode("ascii"))
    print("NOTE production undo/storage design and state architecture remain undecided")


if __name__ == "__main__":
    main()
