#!/usr/bin/env python3
"""ARCH-001 research-only cross-workload equivalence evidence.

Binds equivalent logical outcomes for native AXVEN transfer, issued-token
transfer, and minimal mutable program state across the UTXO baseline,
account/state prototype, and object/resource prototype. No production
consensus module imports this file.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json

from arch001_model import AxvenObject, canonical_bytes, commitment, state_commitment
from arch001_transfer_compare import account_transfer, object_plain, object_transfer, utxo_transfer
from arch001_token_program_compare import (
    account_program_increment,
    account_token_transfer,
    object_program_increment,
    object_token_transfer,
    utxo_program_increment,
    utxo_token_transfer,
)


def replay_rejected_unchanged(apply, state_commit) -> tuple[bool, bool]:
    before = state_commit()
    try:
        apply()
    except (AssertionError, KeyError, ValueError):
        return True, state_commit() == before
    return False, False


def native_rows() -> list[dict[str, object]]:
    u0 = {"genesis:0": {"owner": "alice", "amount": 100}, "genesis:1": {"owner": "bob", "amount": 25}}
    utx = {"txid": "transfer1", "input": "genesis:0", "sender": "alice", "recipient": "bob", "amount": 10}
    a0 = {"alice": {"balance": 100, "sequence": 0}, "bob": {"balance": 25, "sequence": 0}}
    atx = {"sender": "alice", "recipient": "bob", "amount": 10, "sequence": 0}
    o0 = {
        "alice-balance": AxvenObject("alice-balance", "alice", "native-balance", 0, {"amount": 100}, "ed25519"),
        "bob-balance": AxvenObject("bob-balance", "bob", "native-balance", 0, {"amount": 25}, "hybrid-v1"),
    }
    otx = {"sender": "alice", "source_object": "alice-balance", "destination_object": "bob-balance", "source_version": 0, "destination_version": 0, "amount": 10}

    u1, a1, o1 = utxo_transfer(u0, utx), account_transfer(a0, atx), object_transfer(o0, otx)
    checks = [
        ("utxo", lambda: utxo_transfer(u1, utx), lambda: commitment(u1), sum(x["amount"] for x in u1.values())),
        ("account-state", lambda: account_transfer(a1, atx), lambda: commitment(a1), sum(x["balance"] for x in a1.values())),
        ("object-resource", lambda: object_transfer(o1, otx), lambda: commitment(object_plain(o1)), sum(x.data["amount"] for x in o1.values())),
    ]
    rows = []
    for candidate, replay, state_commit, total in checks:
        rejected, unchanged = replay_rejected_unchanged(replay, state_commit)
        rows.append({"candidate": candidate, "logical_total": total, "replay_rejected": rejected, "rejected_state_unchanged": unchanged, "post_commitment": state_commit()})
    assert all(r["logical_total"] == 125 and r["replay_rejected"] and r["rejected_state_unchanged"] for r in rows)
    return rows


def token_rows() -> list[dict[str, object]]:
    u = {"mint:0": {"owner": "alice", "asset": "TOK", "amount": 100}, "bob:0": {"owner": "bob", "asset": "TOK", "amount": 25}}
    a = {"alice": {"TOK": 100, "sequence": 0}, "bob": {"TOK": 25, "sequence": 0}}
    o = {
        "alice:TOK": AxvenObject("alice:TOK", "alice", "token-balance:TOK", 0, {"amount": 100}, "hybrid-v1"),
        "bob:TOK": AxvenObject("bob:TOK", "bob", "token-balance:TOK", 0, {"amount": 25}, "hybrid-v1"),
    }
    spent: set[str] = set()
    utxo_token_transfer(u, spent, "mint:0", 10)
    account_token_transfer(a, "alice", "bob", 10, 0)
    object_token_transfer(o, "alice:TOK", "bob:TOK", 10, 0)
    checks = [
        ("utxo", lambda: utxo_token_transfer(u, spent, "mint:0", 10), lambda: commitment(u), sum(x["amount"] for x in u.values())),
        ("account-state", lambda: account_token_transfer(a, "alice", "bob", 10, 0), lambda: commitment(a), a["alice"]["TOK"] + a["bob"]["TOK"]),
        ("object-resource", lambda: object_token_transfer(o, "alice:TOK", "bob:TOK", 10, 0), lambda: state_commitment(o), sum(x.data["amount"] for x in o.values())),
    ]
    rows = []
    for candidate, replay, state_commit, total in checks:
        rejected, unchanged = replay_rejected_unchanged(replay, state_commit)
        rows.append({"candidate": candidate, "logical_total": total, "replay_rejected": rejected, "rejected_state_unchanged": unchanged, "post_commitment": state_commit()})
    assert all(r["logical_total"] == 125 and r["replay_rejected"] and r["rejected_state_unchanged"] for r in rows)
    return rows


def program_rows() -> list[dict[str, object]]:
    u = {"counter:0": {"owner": "program:counter", "asset": "STATE", "amount": 7}}
    a = {"program:counter": {"counter": 7, "sequence": 0}}
    o = {"counter": AxvenObject("counter", "program:counter", "counter", 0, {"value": 7}, "program-policy")}
    spent: set[str] = set()
    utxo_program_increment(u, spent, "counter:0", "counter:1")
    account_program_increment(a, "program:counter", 0)
    object_program_increment(o, "counter", 0)
    checks = [
        ("utxo", lambda: utxo_program_increment(u, spent, "counter:0", "counter:1"), lambda: commitment(u), u["counter:1"]["amount"]),
        ("account-state", lambda: account_program_increment(a, "program:counter", 0), lambda: commitment(a), a["program:counter"]["counter"]),
        ("object-resource", lambda: object_program_increment(o, "counter", 0), lambda: state_commitment(o), o["counter"].data["value"]),
    ]
    rows = []
    for candidate, replay, state_commit, value in checks:
        rejected, unchanged = replay_rejected_unchanged(replay, state_commit)
        rows.append({"candidate": candidate, "logical_value": value, "replay_rejected": rejected, "rejected_state_unchanged": unchanged, "post_commitment": state_commit()})
    assert all(r["logical_value"] == 8 and r["replay_rejected"] and r["rejected_state_unchanged"] for r in rows)
    return rows


def build_evidence() -> dict[str, object]:
    return {
        "schema": "axven-arch001-cross-workload-equivalence-v1",
        "scope": "research-only; outside production consensus routing",
        "candidates": ["utxo", "account-state", "object-resource"],
        "workloads": [
            {"name": "native-axven-transfer", "logical_initial_total": 125, "logical_transfer": 10, "rows": native_rows()},
            {"name": "issued-token-transfer", "logical_initial_total": 125, "logical_transfer": 10, "rows": token_rows()},
            {"name": "program-counter-increment", "logical_pre_value": 7, "logical_post_value": 8, "rows": program_rows()},
        ],
        "equivalent_logical_outcomes_required": True,
        "replay_fail_closed_and_state_unchanged_required": True,
        "production_cost_claim": False,
        "architecture_selected": False,
    }


def main() -> None:
    first = canonical_bytes(build_evidence())
    second = canonical_bytes(build_evidence())
    assert first == second
    parsed = json.loads(first.decode("ascii"))
    assert len(parsed["workloads"]) == 3
    assert all(len(workload["rows"]) == 3 for workload in parsed["workloads"])
    print("ARCH-001 cross-workload equivalence evidence: 18/18 GREEN")
    print("evidence_sha256", hashlib.sha256(first).hexdigest())
    print(first.decode("ascii"))
    print("NOTE equivalent logical outcomes and replay fail-closed/no-partial-mutation are bound across all three candidates; no architecture selected")


if __name__ == "__main__":
    main()
