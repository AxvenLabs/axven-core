#!/usr/bin/env python3
"""ARCH-001 research-only program-state conflict evidence.

Equivalent competing mutations are applied to the same committed program state
for the UTXO, account/state, and object/resource candidates. This file is not
imported by production consensus routing and does not select an architecture.
"""
from __future__ import annotations

from copy import deepcopy

from arch001_model import AxvenObject, account_root, state_commitment, utxo_root
from arch001_token_program_compare import (
    account_program_increment,
    object_program_increment,
    utxo_program_increment,
)


def rejected(fn) -> str:
    try:
        fn()
    except ValueError as exc:
        return str(exc)
    raise AssertionError("competing transition unexpectedly accepted")


def roots(u, a, o):
    return (utxo_root(u), account_root(a), state_commitment(o))


def execute_once():
    u0 = {"counter:0": {"owner": "program:counter", "asset": "STATE", "amount": 7}}
    a0 = {"program:counter": {"counter": 7, "sequence": 0}}
    o0 = {"counter": AxvenObject("counter", "program:counter", "counter", 0, {"value": 7}, "program-policy")}

    pre = roots(u0, a0, o0)
    u, a, o, spent = deepcopy(u0), deepcopy(a0), deepcopy(o0), set()
    utxo_program_increment(u, spent, "counter:0", "counter:1")
    account_program_increment(a, "program:counter", 0)
    object_program_increment(o, "counter", 0)
    accepted = roots(u, a, o)

    errors = (
        rejected(lambda: utxo_program_increment(u, spent, "counter:0", "counter:2")),
        rejected(lambda: account_program_increment(a, "program:counter", 0)),
        rejected(lambda: object_program_increment(o, "counter", 0)),
    )
    assert errors == (
        "spent-or-missing-program-outpoint",
        "stale-program-sequence",
        "stale-program-object-version",
    )
    assert roots(u, a, o) == accepted

    # Re-execution from the identical committed pre-state must reproduce the
    # accepted branch byte-for-byte for each candidate.
    u2, a2, o2, spent2 = deepcopy(u0), deepcopy(a0), deepcopy(o0), set()
    utxo_program_increment(u2, spent2, "counter:0", "counter:1")
    account_program_increment(a2, "program:counter", 0)
    object_program_increment(o2, "counter", 0)
    assert roots(u2, a2, o2) == accepted

    assert pre != accepted
    return pre, accepted, errors


def main() -> None:
    first = execute_once()
    second = execute_once()
    assert first == second
    pre, accepted, errors = first
    print("ARCH-001 program-state conflict evidence: 8/8 GREEN")
    print("pre_roots=", pre)
    print("accepted_roots=", accepted)
    print("conflict_errors=", errors)
    print("rejected_conflict_preserves_commitment=true")
    print("repeat_execution_identical=true")
    print("architecture_selected=false")


if __name__ == "__main__":
    main()
