#!/usr/bin/env python3
"""ARCH-001 research-only authorization size/cost sensitivity.

Uses the existing Axven crypto implementations as measurement fixtures only.
This file is not imported by production consensus. Timings are diagnostic and
MUST NOT be treated as consensus parameters or SLAs.
"""
from __future__ import annotations

import json
import statistics
import time

import axven

SAMPLES = 7


def canonical_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def median_ns(fn) -> int:
    rows=[]
    for _ in range(SAMPLES):
        start=time.perf_counter_ns(); fn(); rows.append(time.perf_counter_ns()-start)
    return int(statistics.median(rows))


def main() -> None:
    message=axven.sha256(b"arch-001-auth-cost-sensitivity").encode("ascii")
    ed=axven.Wallet(); ml=axven.MLDSAWallet(); hy=axven.HybridWallet()

    fixtures=[]
    ed_input={"prev_txid":"11"*32,"index":0,"signature":axven._b64e(ed.sign(message)),"public_key":axven._b64e(ed.public_key)}
    fixtures.append(("ed25519",ed_input,{"amount":50000,"recipient":ed.address,"coinbase":False,"height":1},100))

    ml_input={"prev_txid":"22"*32,"index":0,"scheme":axven.SCHEME_ML_DSA,"signature":axven._b64e(ml.sign(message)),"public_key":axven._b64e(ml.public_key)}
    fixtures.append(("ml-dsa-44",ml_input,{"amount":50000,"recipient":ml.address,"coinbase":False,"height":1},5000))

    hy_input={"prev_txid":"33"*32,"index":0,"scheme":axven.SCHEME_HYBRID,"ed_signature":axven._b64e(hy.ed_wallet.sign(message)),"ed_public_key":axven._b64e(hy.ed_public_key),"ml_signature":axven._b64e(hy.ml_wallet.sign(message)),"ml_public_key":axven._b64e(hy.ml_public_key)}
    fixtures.append(("hybrid",hy_input,{"amount":50000,"recipient":hy.address,"coinbase":False,"height":1},3000))

    rows=[]
    for name,witness,utxo,height in fixtures:
        assert axven.verify_input(witness,utxo,message,height)
        size=len(canonical_bytes(witness))
        verify_ns=median_ns(lambda w=witness,u=utxo,h=height: axven.verify_input(w,u,message,h))
        rows.append((name,size,verify_ns))

    assert rows[0][1] < rows[1][1]
    assert rows[0][1] < rows[2][1]
    print("ARCH-001 authorization sensitivity: 5/5 GREEN")
    for name,size,verify_ns in rows:
        print(name,"canonical_witness_bytes",size,"median_verify_ns",verify_ns)


if __name__ == "__main__":
    main()
