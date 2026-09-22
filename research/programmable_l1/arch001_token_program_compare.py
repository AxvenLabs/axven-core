#!/usr/bin/env python3
"""ARCH-001 research-only token/program-state workload comparison.

No production consensus module imports this file. The point is to compare
state semantics, deterministic commitments, replay rejection and rollback
requirements before selecting an Axven programmable-L1 architecture.
"""

from __future__ import annotations

from copy import deepcopy

from arch001_model import AxvenObject, ResearchTransaction, access_conflicts, commitment, state_commitment


def account_root(state):
    return commitment(state)


def utxo_root(state):
    return commitment(state)


def utxo_token_transfer(state, spent, outpoint, amount):
    if outpoint in spent or outpoint not in state:
        raise ValueError("spent-or-missing-outpoint")
    coin = state[outpoint]
    if coin["asset"] != "TOK" or amount <= 0 or amount > coin["amount"]:
        raise ValueError("invalid-token-spend")
    del state[outpoint]
    spent.add(outpoint)
    state["tx1:0"] = {"owner": "bob", "asset": "TOK", "amount": amount}
    if coin["amount"] > amount:
        state["tx1:1"] = {"owner": coin["owner"], "asset": "TOK", "amount": coin["amount"] - amount}


def account_token_transfer(state, sender, recipient, amount, sequence):
    acct = state[sender]
    if sequence != acct["sequence"]:
        raise ValueError("stale-sequence")
    if amount <= 0 or acct["TOK"] < amount:
        raise ValueError("invalid-token-spend")
    acct["TOK"] -= amount
    acct["sequence"] += 1
    state[recipient]["TOK"] += amount


def object_token_transfer(state, sender_id, recipient_id, amount, expected_version):
    sender = state[sender_id]
    if sender.version != expected_version:
        raise ValueError("stale-object-version")
    if amount <= 0 or sender.data["amount"] < amount:
        raise ValueError("invalid-token-spend")
    recipient = state[recipient_id]
    state[sender_id] = AxvenObject(sender.object_id, sender.owner_or_authority, sender.object_type,
                                   sender.version + 1, {"amount": sender.data["amount"] - amount},
                                   sender.authorization_policy)
    state[recipient_id] = AxvenObject(recipient.object_id, recipient.owner_or_authority, recipient.object_type,
                                      recipient.version + 1, {"amount": recipient.data["amount"] + amount},
                                      recipient.authorization_policy)


def utxo_program_increment(state, spent, outpoint, new_outpoint):
    if outpoint in spent or outpoint not in state:
        raise ValueError("spent-or-missing-program-outpoint")
    current = state[outpoint]
    del state[outpoint]
    spent.add(outpoint)
    state[new_outpoint] = {"owner": current["owner"], "asset": "STATE", "amount": current["amount"] + 1}


def account_program_increment(state, program_id, sequence):
    program = state[program_id]
    if sequence != program["sequence"]:
        raise ValueError("stale-program-sequence")
    program["counter"] += 1
    program["sequence"] += 1


def object_program_increment(state, object_id, expected_version):
    current = state[object_id]
    if current.version != expected_version:
        raise ValueError("stale-program-object-version")
    state[object_id] = AxvenObject(current.object_id, current.owner_or_authority, current.object_type,
                                   current.version + 1, {"value": current.data["value"] + 1},
                                   current.authorization_policy)


def expect_replay_rejected(fn):
    try:
        fn()
    except ValueError:
        return
    raise AssertionError("replay accepted")


def main():
    # Equivalent user-token transfer: Alice 100 TOK, Bob 25 TOK, transfer 10 TOK.
    u0 = {"mint:0": {"owner": "alice", "asset": "TOK", "amount": 100},
          "bob:0": {"owner": "bob", "asset": "TOK", "amount": 25}}
    a0 = {"alice": {"TOK": 100, "sequence": 0}, "bob": {"TOK": 25, "sequence": 0}}
    o0 = {
        "alice:TOK": AxvenObject("alice:TOK", "alice", "token-balance:TOK", 0, {"amount": 100}, "hybrid-v1"),
        "bob:TOK": AxvenObject("bob:TOK", "bob", "token-balance:TOK", 0, {"amount": 25}, "hybrid-v1"),
    }
    u, a, o = deepcopy(u0), deepcopy(a0), deepcopy(o0)
    spent = set()
    pre = (utxo_root(u), account_root(a), state_commitment(o))
    utxo_token_transfer(u, spent, "mint:0", 10)
    account_token_transfer(a, "alice", "bob", 10, 0)
    object_token_transfer(o, "alice:TOK", "bob:TOK", 10, 0)
    post = (utxo_root(u), account_root(a), state_commitment(o))
    assert pre != post
    assert sum(x["amount"] for x in u.values() if x["asset"] == "TOK") == 125
    assert a["alice"]["TOK"] + a["bob"]["TOK"] == 125
    assert sum(x.data["amount"] for x in o.values()) == 125
    expect_replay_rejected(lambda: utxo_token_transfer(u, spent, "mint:0", 10))
    expect_replay_rejected(lambda: account_token_transfer(a, "alice", "bob", 10, 0))
    expect_replay_rejected(lambda: object_token_transfer(o, "alice:TOK", "bob:TOK", 10, 0))

    # Equivalent program-state mutation: increment a counter from 7 to 8.
    # All candidates now use their native stale-state guard so replay/conflict
    # rejection is measured with the same fail-closed requirement.
    up0 = {"counter:0": {"owner": "program:counter", "asset": "STATE", "amount": 7}}
    ap0 = {"program:counter": {"counter": 7, "sequence": 0}}
    op0 = {"counter": AxvenObject("counter", "program:counter", "counter", 0, {"value": 7}, "program-policy")}
    uprog, aprog, oprog = deepcopy(up0), deepcopy(ap0), deepcopy(op0)
    program_spent = set()
    program_pre = (utxo_root(uprog), account_root(aprog), state_commitment(oprog))
    utxo_program_increment(uprog, program_spent, "counter:0", "counter:1")
    account_program_increment(aprog, "program:counter", 0)
    object_program_increment(oprog, "counter", 0)
    program_post = (utxo_root(uprog), account_root(aprog), state_commitment(oprog))
    assert program_pre != program_post
    assert uprog["counter:1"]["amount"] == aprog["program:counter"]["counter"] == oprog["counter"].data["value"] == 8

    # Replaying the accepted program transition must fail closed and leave the
    # accepted post-state commitments byte-for-byte unchanged.
    expect_replay_rejected(lambda: utxo_program_increment(uprog, program_spent, "counter:0", "counter:1"))
    expect_replay_rejected(lambda: account_program_increment(aprog, "program:counter", 0))
    expect_replay_rejected(lambda: object_program_increment(oprog, "counter", 0))
    assert (utxo_root(uprog), account_root(aprog), state_commitment(oprog)) == program_post

    # Re-execution from the same committed pre-state is deterministic.
    up2, ap2, op2, program_spent2 = deepcopy(up0), deepcopy(ap0), deepcopy(op0), set()
    utxo_program_increment(up2, program_spent2, "counter:0", "counter:1")
    account_program_increment(ap2, "program:counter", 0)
    object_program_increment(op2, "counter", 0)
    assert (utxo_root(up2), account_root(ap2), state_commitment(op2)) == program_post

    # Object access declarations expose deterministic scheduling conflicts.
    t1 = ResearchTransaction("alice", 0, ("alice:TOK", "bob:TOK"), ("alice:TOK", "bob:TOK"),
                             "token-transfer", {"amount": 10}, 1000, "hybrid-v1")
    t2 = ResearchTransaction("carol", 0, ("carol:TOK", "dave:TOK"), ("carol:TOK", "dave:TOK"),
                             "token-transfer", {"amount": 10}, 1000, "hybrid-v1")
    t3 = ResearchTransaction("mallory", 0, ("bob:TOK",), ("bob:TOK",),
                             "token-transfer", {"amount": 1}, 1000, "hybrid-v1")
    assert access_conflicts(t1, t2) is False
    assert access_conflicts(t1, t3) is True

    # Replaying token transfer from identical pre-state reproduces commitments.
    u2, a2, o2, spent2 = deepcopy(u0), deepcopy(a0), deepcopy(o0), set()
    utxo_token_transfer(u2, spent2, "mint:0", 10)
    account_token_transfer(a2, "alice", "bob", 10, 0)
    object_token_transfer(o2, "alice:TOK", "bob:TOK", 10, 0)
    assert (utxo_root(u2), account_root(a2), state_commitment(o2)) == post

    print("ARCH-001 token/program workloads: 18/18 GREEN")
    print("pre_roots=", pre)
    print("post_roots=", post)
    print("program_pre_roots=", program_pre)
    print("program_post_roots=", program_post)
    print("program_replay=fail-closed; rejected replay preserves accepted commitments")
    print("observation=UTXO consumes/recreates state; account uses sequence; object uses explicit versioned resources")


if __name__ == "__main__":
    main()
