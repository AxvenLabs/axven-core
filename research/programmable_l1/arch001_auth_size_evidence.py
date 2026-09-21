#!/usr/bin/env python3
"""ARCH-001 research-only deterministic authorization-size evidence.

Separates canonical witness-size sensitivity from nondeterministic verification
wall-clock timing. This file is not imported by production consensus and does
not select a production PQ scheme or state architecture.
"""
from __future__ import annotations

import json

import axven


def canonical_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def main() -> None:
    message = axven.sha256(b"arch-001-auth-size-evidence").encode("ascii")
    ed = axven.Wallet()
    ml = axven.MLDSAWallet()
    hy = axven.HybridWallet()

    fixtures = [
        ("ed25519", {
            "prev_txid": "11" * 32,
            "index": 0,
            "signature": axven._b64e(ed.sign(message)),
            "public_key": axven._b64e(ed.public_key),
        }, {"amount": 50000, "recipient": ed.address, "coinbase": False, "height": 1}, 100),
        ("ml-dsa-44", {
            "prev_txid": "22" * 32,
            "index": 0,
            "scheme": axven.SCHEME_ML_DSA,
            "signature": axven._b64e(ml.sign(message)),
            "public_key": axven._b64e(ml.public_key),
        }, {"amount": 50000, "recipient": ml.address, "coinbase": False, "height": 1}, 5000),
        ("hybrid", {
            "prev_txid": "33" * 32,
            "index": 0,
            "scheme": axven.SCHEME_HYBRID,
            "ed_signature": axven._b64e(hy.ed_wallet.sign(message)),
            "ed_public_key": axven._b64e(hy.ed_public_key),
            "ml_signature": axven._b64e(hy.ml_wallet.sign(message)),
            "ml_public_key": axven._b64e(hy.ml_public_key),
        }, {"amount": 50000, "recipient": hy.address, "coinbase": False, "height": 1}, 3000),
    ]

    rows = []
    for name, witness, utxo, height in fixtures:
        assert axven.verify_input(witness, utxo, message, height)
        rows.append({"scheme": name, "canonical_witness_bytes": len(canonical_bytes(witness))})

    by_name = {row["scheme"]: row["canonical_witness_bytes"] for row in rows}
    assert by_name["ed25519"] < by_name["ml-dsa-44"]
    assert by_name["ed25519"] < by_name["hybrid"]

    evidence = {
        "schema": "axven-arch001-auth-size-v1",
        "scope": "research-only; outside production consensus routing",
        "rows": rows,
        "timing_included": False,
        "production_pq_scheme_selected": False,
        "architecture_selected": False,
    }
    print("ARCH-001 deterministic authorization-size evidence: 4/4 GREEN")
    print(canonical_bytes(evidence).decode("ascii"))


if __name__ == "__main__":
    main()
