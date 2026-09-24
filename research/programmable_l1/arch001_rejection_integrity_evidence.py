#!/usr/bin/env python3
"""ARCH-001 research-only rejection-integrity evidence."""
from copy import deepcopy
import hashlib
from arch001_model import AxvenObject, canonical_bytes, commitment, state_commitment
from arch001_token_program_compare import account_program_increment, object_program_increment, utxo_program_increment

def build_evidence():
    u = {"counter:0": {"owner": "program:counter", "asset": "STATE", "amount": 7}}
    a = {"program:counter": {"counter": 7, "sequence": 0}}
    o = {"counter": AxvenObject("counter", "program:counter", "counter", 0, {"value": 7}, "program-policy")}
    spent = set()
    utxo_program_increment(u, spent, "counter:0", "counter:1")
    account_program_increment(a, "program:counter", 0)
    object_program_increment(o, "counter", 0)
    accepted = {"utxo": commitment(u), "account-state": commitment(a), "object-resource": state_commitment(o)}
    rejected = {}
    for name, fn, root in (
        ("utxo", lambda: utxo_program_increment(u, spent, "counter:0", "counter:1"), lambda: commitment(u)),
        ("account-state", lambda: account_program_increment(a, "program:counter", 0), lambda: commitment(a)),
        ("object-resource", lambda: object_program_increment(o, "counter", 0), lambda: state_commitment(o)),
    ):
        try:
            fn()
            ok = False
        except ValueError:
            ok = True
        rejected[name] = {"replay_rejected": ok, "accepted_post_state_unchanged": root() == accepted[name]}
    assert all(x["replay_rejected"] and x["accepted_post_state_unchanged"] for x in rejected.values())
    assert u["counter:1"]["amount"] == a["program:counter"]["counter"] == o["counter"].data["value"] == 8
    return {"schema": "axven-arch001-rejection-integrity-v1", "scope": "research-only; outside production consensus routing", "workload": "mutable-program-state-replay", "candidates": rejected, "architecture_selected": False}

def main():
    first = canonical_bytes(build_evidence())
    second = canonical_bytes(build_evidence())
    assert first == second
    print("ARCH-001 rejection-integrity evidence: 6/6 GREEN")
    print("evidence_sha256", hashlib.sha256(first).hexdigest())
    print(first.decode("ascii"))
    print("NOTE replay rejection preserves accepted post-state; no architecture selected")

if __name__ == "__main__":
    main()
