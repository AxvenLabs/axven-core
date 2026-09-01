#!/usr/bin/env python3
"""PERF-001 deterministic Axven CPU baseline and hotspot profile.

This is measurement tooling, not a performance gate.  GitHub-hosted runners are
noisy, so timings are reported as medians and must not become consensus or SLA
inputs.  The purpose is to decide which Python hot path, if any, deserves a
small native accelerator.
"""
from __future__ import annotations

import cProfile
import io
import json
import platform
import pstats
import statistics
import sys
import time
import tracemalloc
from typing import Callable

import axven
import p2p
import rpc
import wallet


SAMPLES = 5


def _bench(name: str, fn: Callable[[], object], iterations: int, samples: int = SAMPLES):
    if iterations < 1 or samples < 1:
        raise ValueError("invalid benchmark dimensions")
    # One unmeasured warmup catches lazy imports/backend initialization without
    # contaminating the steady-state samples.
    fn()
    totals_ns = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        for _i in range(iterations):
            fn()
        totals_ns.append(time.perf_counter_ns() - start)
    median_total = statistics.median(totals_ns)
    median_ns = median_total / iterations
    return {
        "name": name,
        "iterations_per_sample": iterations,
        "samples": samples,
        "median_ns_per_op": round(median_ns, 1),
        "median_ms_per_op": round(median_ns / 1_000_000.0, 6),
        "ops_per_second": round(1_000_000_000.0 / median_ns, 2),
    }


def _peak_python_bytes(fn: Callable[[], object]) -> int:
    tracemalloc.start()
    try:
        fn()
        _current, peak = tracemalloc.get_traced_memory()
        return int(peak)
    finally:
        tracemalloc.stop()


def _make_utxo(count: int):
    out = {}
    recipients = ["N" + axven.sha256(f"perf-address-{i}".encode())[:40] for i in range(64)]
    for i in range(count):
        out[f"{i:064x}:0"] = {
            "amount": 1000 + i,
            "recipient": recipients[i % len(recipients)],
            "coinbase": False,
            "height": 1 + (i % 100),
        }
    return out


def _crypto_fixtures(message: bytes):
    ed = axven.Wallet()
    ed_utxo = {"amount": 50_000, "recipient": ed.address, "coinbase": False, "height": 1}
    ed_input = {
        "prev_txid": "11" * 32,
        "index": 0,
        "signature": axven._b64e(ed.sign(message)),
        "public_key": axven._b64e(ed.public_key),
    }

    ml = axven.MLDSAWallet()
    ml_utxo = {"amount": 50_000, "recipient": ml.address, "coinbase": False, "height": 1}
    ml_input = {
        "prev_txid": "22" * 32,
        "index": 0,
        "scheme": axven.SCHEME_ML_DSA,
        "signature": axven._b64e(ml.sign(message)),
        "public_key": axven._b64e(ml.public_key),
    }

    hybrid = axven.HybridWallet()
    hybrid_utxo = {
        "amount": 50_000,
        "recipient": hybrid.address,
        "coinbase": False,
        "height": 1,
    }
    hybrid_input = {
        "prev_txid": "33" * 32,
        "index": 0,
        "scheme": axven.SCHEME_HYBRID,
        "ed_signature": axven._b64e(hybrid.ed_wallet.sign(message)),
        "ed_public_key": axven._b64e(hybrid.ed_public_key),
        "ml_signature": axven._b64e(hybrid.ml_wallet.sign(message)),
        "ml_public_key": axven._b64e(hybrid.ml_public_key),
    }
    return (ed_input, ed_utxo), (ml_input, ml_utxo), (hybrid_input, hybrid_utxo)


def _build_context():
    small_utxo = _make_utxo(1_000)
    large_utxo = _make_utxo(10_000)

    tx = axven.Transaction(
        [axven.TxInput("44" * 32, 7, signature="AA==", public_key="AA==")],
        [axven.TxOutput(12345, "N" + "5" * 40)],
    )
    tx_dict = tx.to_dict()
    hashes = [axven.sha256(f"perf-tx-{i}".encode()) for i in range(1_000)]
    block = axven.Block(
        height=1,
        timestamp=1,
        previous_hash="00" * 32,
        merkle_root=axven.merkle_root(hashes),
        target=axven.MAX_TARGET,
        transactions=[tx_dict] * 1_000,
        nonce=0,
        miner="N" + "6" * 40,
        utxo_state_root="00" * 32,
    )

    tree = axven.SparseMerkleTree(small_utxo)
    proof_op = next(iter(small_utxo))
    proof = tree.prove(proof_op)
    update_counter = [0]

    def incremental_update():
        update_counter[0] += 1
        value = dict(small_utxo[proof_op])
        value["amount"] += update_counter[0] & 1
        tree.update(proof_op, value)

    message = axven.sha256(b"axven-perf-001").encode("ascii")
    crypto = _crypto_fixtures(message)

    parser_payload = b'{"items":[' + (b'0,' * 1500) + b'0],"text":"[{,}]"}'

    return {
        "small_utxo": small_utxo,
        "large_utxo": large_utxo,
        "tx": tx,
        "hashes": hashes,
        "block": block,
        "tree": tree,
        "proof_op": proof_op,
        "proof": proof,
        "incremental_update": incremental_update,
        "message": message,
        "crypto": crypto,
        "parser_payload": parser_payload,
    }


def _measure(ctx):
    (ed_input, ed_utxo), (ml_input, ml_utxo), (hy_input, hy_utxo) = ctx["crypto"]
    msg = ctx["message"]
    proof = ctx["proof"]

    tests = [
        ("tx.txid", lambda: ctx["tx"].txid(), 20_000),
        ("tx.serialized_size", lambda: axven.serialized_transaction_size(ctx["tx"]), 20_000),
        ("merkle_root.1000_hashes", lambda: axven.merkle_root(ctx["hashes"]), 100),
        ("block.serialized_size.1000_txs", lambda: axven.serialized_block_size(ctx["block"]), 100),
        ("utxo_root.1000", lambda: axven.utxo_root(ctx["small_utxo"]), 20),
        ("utxo_root.10000", lambda: axven.utxo_root(ctx["large_utxo"]), 3),
        ("smt_reference.1000", lambda: axven.smt_root_reference(ctx["small_utxo"]), 3),
        ("smt_incremental.single_update", ctx["incremental_update"], 2_000),
        (
            "smt_proof_verify",
            lambda: axven.smt_verify_proof(
                ctx["proof_op"], proof["value"], proof["siblings"], proof["root"]
            ),
            2_000,
        ),
        ("verify.ed25519", lambda: axven.verify_input(ed_input, ed_utxo, msg, 100), 5_000),
        ("verify.mldsa44", lambda: axven.verify_input(ml_input, ml_utxo, msg, 5_000), 500),
        ("verify.hybrid", lambda: axven.verify_input(hy_input, hy_utxo, msg, 3_000), 300),
        ("p2p.json_preflight", lambda: p2p._preflight_json_nesting(ctx["parser_payload"]), 10_000),
        ("rpc.json_preflight", lambda: rpc._preflight_json_nesting(ctx["parser_payload"]), 10_000),
        ("wallet.json_preflight", lambda: wallet._preflight_backup_json_nesting(ctx["parser_payload"]), 10_000),
    ]
    results = []
    for name, fn, iterations in tests:
        row = _bench(name, fn, iterations)
        results.append(row)
        print(
            f"PERF {name:34s} "
            f"{row['median_ms_per_op']:12.6f} ms/op "
            f"{row['ops_per_second']:12.2f} ops/s"
        )
    return results


def _profile(ctx):
    (ed_input, ed_utxo), (ml_input, ml_utxo), _hybrid = ctx["crypto"]
    msg = ctx["message"]
    profiler = cProfile.Profile()
    profiler.enable()
    for _ in range(2_000):
        ctx["tx"].txid()
    for _ in range(3):
        axven.utxo_root(ctx["large_utxo"])
    for _ in range(2):
        axven.smt_root_reference(ctx["small_utxo"])
    for _ in range(500):
        ctx["incremental_update"]()
    for _ in range(2_000):
        p2p._preflight_json_nesting(ctx["parser_payload"])
    for _ in range(1_000):
        axven.verify_input(ed_input, ed_utxo, msg, 100)
    for _ in range(200):
        axven.verify_input(ml_input, ml_utxo, msg, 5_000)
    profiler.disable()

    stream = io.StringIO()
    pstats.Stats(profiler, stream=stream).strip_dirs().sort_stats("cumulative").print_stats(30)
    text = stream.getvalue()
    print("\nPERF-001 CPROFILE TOP 30 (cumulative)\n" + text)
    return text


def main():
    ctx = _build_context()
    results = _measure(ctx)
    memory = {
        "utxo_root_10000_peak_python_bytes": _peak_python_bytes(
            lambda: axven.utxo_root(ctx["large_utxo"])
        ),
        "smt_reference_1000_peak_python_bytes": _peak_python_bytes(
            lambda: axven.smt_root_reference(ctx["small_utxo"])
        ),
        "smt_rebuild_1000_peak_python_bytes": _peak_python_bytes(
            lambda: axven.SparseMerkleTree(ctx["small_utxo"])
        ),
    }
    _profile(ctx)

    payload = {
        "schema": "axven-perf-001-v1",
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "note": "Shared-runner measurements are diagnostic, not consensus/SLA inputs.",
        "benchmarks": results,
        "python_memory": memory,
    }
    print("PERF-001-JSON " + json.dumps(payload, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
