#!/usr/bin/env python3
"""ARCH-001 research-only program-state rollback/reorg evidence.

Compares restoration and alternate-branch behavior for the same minimal
counter workload across UTXO, account/state, and object/resource prototypes.
This fixture is outside production consensus routing and selects no architecture.
"""
from __future__ import annotations

from copy import deepcopy

from arch001_model import AxvenObject, state_commitment
from arch001_token_program_compare import (
    account_program_increment,
    account_root,
    object_program_increment,
    utxo_program_increment,
    utxo_root,
)


def roots(u, a, o):
    return (utxo_root(u), account_root(a), state_commitment(o))


def values(u, a, o, outpoint):
    return (
        u[outpoint]["amount"],
        a["program:counter"]["counter"],
        o["counter"].data["value"],
    )


def advance(u, a, o, spent, start: int, steps: int):
    outpoint = f"counter:{start}"
    for i in range(steps):
        next_outpoint = f"counter:{start + i + 1}"
        utxo_program_increment(u, spent, outpoint, next_outpoint)
        account_program_increment(a, "program:counter", start + i)
        object_program_increment(o, "counter", start + i)
        outpoint = next_outpoint
    return outpoint


def main() -> None:
    u0 = {"counter:0": {"owner": "program:counter", "asset": "STATE", "amount": 7}}
    a0 = {"program:counter": {"counter": 7, "sequence": 0}}
    o0 = {"counter": AxvenObject("counter", "program:counter", "counter", 0, {"value": 7}, "program-policy")}

    # Canonical branch: 7 -> 8 -> 9 -> 10, retaining an exact checkpoint at 8.
    u, a, o, spent = deepcopy(u0), deepcopy(a0), deepcopy(o0), set()
    checkpoint_outpoint = advance(u, a, o, spent, 0, 1)
    checkpoint = (deepcopy(u), deepcopy(a), deepcopy(o), deepcopy(spent))
    checkpoint_roots = roots(u, a, o)
    assert values(u, a, o, checkpoint_outpoint) == (8, 8, 8)

    tip_outpoint = advance(u, a, o, spent, 1, 2)
    canonical_tip = roots(u, a, o)
    assert values(u, a, o, tip_outpoint) == (10, 10, 10)

    # Roll back to the same committed checkpoint and replay the identical suffix.
    ru, ra, ro, rspent = deepcopy(checkpoint)
    assert roots(ru, ra, ro) == checkpoint_roots
    replay_tip_outpoint = advance(ru, ra, ro, rspent, 1, 2)
    assert roots(ru, ra, ro) == canonical_tip
    assert values(ru, ra, ro, replay_tip_outpoint) == (10, 10, 10)

    # Alternate branch from the exact checkpoint executes one transition only.
    # It must be deterministic and must not accidentally equal the old tip.
    au, aa, ao, aspent = deepcopy(checkpoint)
    alt_outpoint = advance(au, aa, ao, aspent, 1, 1)
    alternate_tip = roots(au, aa, ao)
    assert alternate_tip != canonical_tip
    assert values(au, aa, ao, alt_outpoint) == (9, 9, 9)

    # Re-executing that alternate branch from the checkpoint is byte-identical.
    au2, aa2, ao2, aspent2 = deepcopy(checkpoint)
    alt_outpoint2 = advance(au2, aa2, ao2, aspent2, 1, 1)
    assert roots(au2, aa2, ao2) == alternate_tip
    assert values(au2, aa2, ao2, alt_outpoint2) == (9, 9, 9)

    print("ARCH-001 program-state rollback/reorg evidence: 8/8 GREEN")
    print("checkpoint_roots=", checkpoint_roots)
    print("canonical_tip_roots=", canonical_tip)
    print("alternate_tip_roots=", alternate_tip)
    print("observation=all candidates restore the same research checkpoint, reproduce the same suffix, and diverge deterministically on an alternate branch")
    print("NOTE checkpoint deepcopy is a research oracle, not a production undo/storage design")


if __name__ == "__main__":
    main()
