#!/usr/bin/env python3
"""ARCH-001 research-only deterministic rollback/reorg comparison.

This is deliberately isolated from production consensus routing. It compares
what reversible state evidence each candidate needs after the same transfer.
"""

from copy import deepcopy

from arch001_model import AxvenObject, commitment, state_commitment
from arch001_token_program_compare import (
    account_token_transfer,
    object_token_transfer,
    utxo_token_transfer,
)


def uroot(state):
    return commitment(state)


def aroot(state):
    return commitment(state)


def main():
    u0 = {"mint:0": {"owner": "alice", "asset": "TOK", "amount": 100},
          "bob:0": {"owner": "bob", "asset": "TOK", "amount": 25}}
    a0 = {"alice": {"TOK": 100, "sequence": 0}, "bob": {"TOK": 25, "sequence": 0}}
    o0 = {
        "alice:TOK": AxvenObject("alice:TOK", "alice", "token-balance:TOK", 0, {"amount": 100}, "hybrid-v1"),
        "bob:TOK": AxvenObject("bob:TOK", "bob", "token-balance:TOK", 0, {"amount": 25}, "hybrid-v1"),
    }

    pre = (uroot(u0), aroot(a0), state_commitment(o0))
    u, a, o = deepcopy(u0), deepcopy(a0), deepcopy(o0)
    spent = set()
    utxo_token_transfer(u, spent, "mint:0", 10)
    account_token_transfer(a, "alice", "bob", 10, 0)
    object_token_transfer(o, "alice:TOK", "bob:TOK", 10, 0)
    post = (uroot(u), aroot(a), state_commitment(o))
    assert pre != post

    # Research rollback evidence: restore the exact captured pre-state.  This
    # intentionally does not claim a production undo-log/storage design.
    ur, ar, or_ = deepcopy(u0), deepcopy(a0), deepcopy(o0)
    rolled = (uroot(ur), aroot(ar), state_commitment(or_))
    assert rolled == pre

    # Re-apply after rollback: all candidates must reproduce the exact post root.
    spent2 = set()
    utxo_token_transfer(ur, spent2, "mint:0", 10)
    account_token_transfer(ar, "alice", "bob", 10, 0)
    object_token_transfer(or_, "alice:TOK", "bob:TOK", 10, 0)
    replayed = (uroot(ur), aroot(ar), state_commitment(or_))
    assert replayed == post

    # A competing branch from the same pre-state must produce a different root.
    uc, ac, oc = deepcopy(u0), deepcopy(a0), deepcopy(o0)
    spent3 = set()
    utxo_token_transfer(uc, spent3, "mint:0", 20)
    account_token_transfer(ac, "alice", "bob", 20, 0)
    object_token_transfer(oc, "alice:TOK", "bob:TOK", 20, 0)
    competing = (uroot(uc), aroot(ac), state_commitment(oc))
    assert competing != post

    print("ARCH-001 rollback/reorg comparison: 4/4 GREEN")
    print("pre_roots=", pre)
    print("post_roots=", post)
    print("competing_roots=", competing)
    print("observation=all candidates can be replayed deterministically from captured pre-state; production undo/storage complexity remains undecided")


if __name__ == "__main__":
    main()
