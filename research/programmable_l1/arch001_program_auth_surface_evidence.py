#!/usr/bin/env python3
"""ARCH-001 research-only program-state authorization/state surface evidence.

Couples the existing eight-step mutable program workload with deterministic
canonical witness-size sensitivity for classical, ML-DSA-44 and hybrid auth.
The values are research representations only: not production wire, fee,
storage or verification-cost claims, and no production PQ scheme is selected.
"""
from __future__ import annotations

import json

import axven

from arch001_program_sequence_evidence import run_once
from arch001_model import commitment


def canonical_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def witness_sizes() -> dict[str, int]:
    message = axven.sha256(b"arch-001-program-auth-surface").encode("ascii")
    ed = axven.Wallet()
    ml = axven.MLDSAWallet()
    hy = axven.HybridWallet()
    witnesses = {
        "ed25519": {
            "signature": axven._b64e(ed.sign(message)),
            "public_key": axven._b64e(ed.public_key),
        },
        "ml-dsa-44": {
            "scheme": axven.SCHEME_ML_DSA,
            "signature": axven._b64e(ml.sign(message)),
            "public_key": axven._b64e(ml.public_key),
        },
        "hybrid": {
            "scheme": axven.SCHEME_HYBRID,
            "ed_signature": axven._b64e(hy.ed_wallet.sign(message)),
            "ed_public_key": axven._b64e(hy.ed_public_key),
            "ml_signature": axven._b64e(hy.ml_wallet.sign(message)),
            "ml_public_key": axven._b64e(hy.ml_public_key),
        },
    }
    return {name: len(canonical_bytes(witness)) for name, witness in witnesses.items()}


def build_evidence() -> dict[str, object]:
    sequence = run_once()
    sizes = witness_sizes()
    assert sizes["ed25519"] < sizes["ml-dsa-44"]
    assert sizes["ed25519"] < sizes["hybrid"]

    rows = []
    for row in sequence["rows"]:
        state_bytes = {
            candidate: row[candidate]["state_bytes"]
            for candidate in ("utxo", "account-state", "object-resource")
        }
        rows.append({
            "step": row["step"],
            "counter": row["counter"],
            "state_bytes": state_bytes,
            "auth_witness_bytes": sizes,
            "combined_research_surface_bytes": {
                candidate: {scheme: state_bytes[candidate] + size for scheme, size in sizes.items()}
                for candidate in state_bytes
            },
        })

    return {
        "schema": "axven-arch001-program-auth-surface-v1",
        "scope": "research-only; outside production consensus routing",
        "workload": "eight sequential counter increments from 7 to 15",
        "rows": rows,
        "timing_included": False,
        "production_wire_fee_storage_claim": False,
        "production_pq_scheme_selected": False,
        "architecture_selected": False,
    }


def main() -> None:
    first = build_evidence()
    second = build_evidence()
    first_bytes = canonical_bytes(first)
    second_bytes = canonical_bytes(second)
    assert first_bytes == second_bytes
    assert len(first["rows"]) == 8
    print("ARCH-001 program auth/state surface evidence: 5/5 GREEN")
    print("evidence_sha256", commitment(first))
    print(first_bytes.decode("ascii"))
    print("NOTE combined bytes are research sensitivity only; no architecture or production PQ scheme selected")


if __name__ == "__main__":
    main()
