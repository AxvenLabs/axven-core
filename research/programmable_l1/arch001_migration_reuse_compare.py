#!/usr/bin/env python3
"""ARCH-001 research-only migration/reuse impact evidence.

This is an architecture comparison fixture. It is not imported by production
consensus and does not select a final state model.
"""
from __future__ import annotations

import json


COMPONENTS = (
    "block-chainwork-reorg",
    "p2p-bounded-messages",
    "persistent-storage-replay",
    "sparse-merkle-commitment",
    "rpc-operator-boundary",
    "ed25519-authorization",
    "ml-dsa-44-authorization",
    "hybrid-authorization",
    "utxo-transition-semantics",
    "wallet-state-model",
    "programmable-execution-routing",
)

# Values are deliberately qualitative compatibility classes rather than scores.
# "preserve" means the existing component boundary can remain conceptually
# intact; "adapt" means the boundary is reusable but state semantics change;
# "replace" means candidate-specific semantics are required; "new" means no
# production component exists and research must not pretend otherwise.
MATRIX = {
    "utxo": {
        "block-chainwork-reorg": "preserve",
        "p2p-bounded-messages": "preserve",
        "persistent-storage-replay": "preserve",
        "sparse-merkle-commitment": "preserve",
        "rpc-operator-boundary": "preserve",
        "ed25519-authorization": "preserve",
        "ml-dsa-44-authorization": "preserve",
        "hybrid-authorization": "preserve",
        "utxo-transition-semantics": "preserve",
        "wallet-state-model": "preserve",
        "programmable-execution-routing": "new",
    },
    "account": {
        "block-chainwork-reorg": "preserve",
        "p2p-bounded-messages": "adapt",
        "persistent-storage-replay": "adapt",
        "sparse-merkle-commitment": "adapt",
        "rpc-operator-boundary": "adapt",
        "ed25519-authorization": "preserve",
        "ml-dsa-44-authorization": "preserve",
        "hybrid-authorization": "preserve",
        "utxo-transition-semantics": "replace",
        "wallet-state-model": "adapt",
        "programmable-execution-routing": "new",
    },
    "object-resource": {
        "block-chainwork-reorg": "preserve",
        "p2p-bounded-messages": "adapt",
        "persistent-storage-replay": "adapt",
        "sparse-merkle-commitment": "adapt",
        "rpc-operator-boundary": "adapt",
        "ed25519-authorization": "preserve",
        "ml-dsa-44-authorization": "preserve",
        "hybrid-authorization": "preserve",
        "utxo-transition-semantics": "replace",
        "wallet-state-model": "adapt",
        "programmable-execution-routing": "new",
    },
}


def canonical_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def main() -> None:
    assert tuple(MATRIX) == ("utxo", "account", "object-resource")
    assert all(tuple(MATRIX[candidate]) == COMPONENTS for candidate in MATRIX)

    # Existing authorization implementations are candidate-independent fixtures:
    # changing state architecture must not silently weaken crypto authorization.
    for candidate in MATRIX:
        for component in (
            "ed25519-authorization",
            "ml-dsa-44-authorization",
            "hybrid-authorization",
        ):
            assert MATRIX[candidate][component] == "preserve"

    # Account/object candidates explicitly acknowledge that current UTXO state
    # transition semantics cannot be relabelled as a new model.
    assert MATRIX["account"]["utxo-transition-semantics"] == "replace"
    assert MATRIX["object-resource"]["utxo-transition-semantics"] == "replace"

    # No candidate is allowed to claim an existing production programmable
    # execution route: that remains new/research-only.
    assert all(MATRIX[c]["programmable-execution-routing"] == "new" for c in MATRIX)

    first = canonical_bytes(MATRIX)
    second = canonical_bytes({k: MATRIX[k] for k in reversed(tuple(MATRIX))})
    assert first == second

    print("ARCH-001 migration/reuse evidence: 6/6 GREEN")
    print(first.decode("ascii"))
    print("NOTE compatibility classes are research evidence, not architecture scores")


if __name__ == "__main__":
    main()
