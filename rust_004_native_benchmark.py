#!/usr/bin/env python3
"""RUST-004: correctness-first Python vs native Sparse-Merkle benchmark."""
from __future__ import annotations

import gc
import json
import platform
import statistics
import time
from pathlib import Path
from typing import Callable

import axven
import axven_native

ROOT = Path(__file__).resolve().parent
SAMPLES = 5


def _make_utxo(count: int):
    if type(count) is not int or count < 0:
        raise ValueError("invalid UTXO count")
    recipients = ["N" + axven.sha256(f"rust004-address-{i}".encode())[:40] for i in range(64)]
    out = {}
    for i in range(count):
        out[f"{i:064x}:0"] = {
            "amount": 1000 + i,
            "recipient": recipients[i % len(recipients)],
            "coinbase": False,
            "height": 1 + (i % 100),
        }
    return out


def _rows(utxo):
    return [
        (
            op,
            value["amount"],
            value["recipient"],
            value["coinbase"],
            value["height"],
        )
        for op, value in utxo.items()
    ]


def _bench(fn: Callable[[], object], iterations: int, samples: int = SAMPLES):
    if type(iterations) is not int or iterations < 1:
        raise ValueError("invalid benchmark iterations")
    if type(samples) is not int or samples < 3:
        raise ValueError("invalid benchmark samples")

    fn()  # unmeasured warmup
    totals = []
    for _ in range(samples):
        gc.collect()
        start = time.perf_counter_ns()
        for _i in range(iterations):
            fn()
        totals.append(time.perf_counter_ns() - start)
    median_total = statistics.median(totals)
    median_ns = median_total / iterations
    return {
        "iterations_per_sample": iterations,
        "samples": samples,
        "median_ns_per_op": round(median_ns, 1),
        "median_ms_per_op": round(median_ns / 1_000_000.0, 6),
        "ops_per_second": round(1_000_000_000.0 / median_ns, 2),
    }


def _assert_production_python_only():
    for name in ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py"):
        source = (ROOT / name).read_text(encoding="utf-8")
        assert "axven_native" not in source, name


def _measure_case(count: int, python_iterations: int, native_iterations: int):
    utxo = _make_utxo(count)
    rows = _rows(utxo)

    # Correctness is an absolute prerequisite for timing.
    python_root = axven.smt_root_reference(utxo)
    native_root = axven_native.smt_root_mirror(rows)
    assert native_root == python_root, (count, native_root, python_root)

    reversed_rows = list(reversed(rows))
    assert axven_native.smt_root_mirror(reversed_rows) == python_root
    if rows:
        rotated_rows = rows[1:] + rows[:1]
        assert axven_native.smt_root_mirror(rotated_rows) == python_root

    python_result = _bench(
        lambda: axven.smt_root_reference(utxo),
        python_iterations,
    )
    prepared_result = _bench(
        lambda: axven_native.smt_root_mirror(rows),
        native_iterations,
    )
    end_to_end_result = _bench(
        lambda: axven_native.smt_root_mirror(_rows(utxo)),
        native_iterations,
    )

    py_ns = python_result["median_ns_per_op"]
    prepared_ns = prepared_result["median_ns_per_op"]
    end_to_end_ns = end_to_end_result["median_ns_per_op"]
    return {
        "utxos": count,
        "root": python_root,
        "python_reference": python_result,
        "rust_prepared_rows": prepared_result,
        "rust_end_to_end": end_to_end_result,
        "speedup_prepared_rows": round(py_ns / prepared_ns, 3),
        "speedup_end_to_end": round(py_ns / end_to_end_ns, 3),
    }


def main() -> None:
    _assert_production_python_only()

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    assert axven.CHAIN_CONFIG["smt_activation_height"] == 10_000
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2_000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5_000

    cases = (
        (0, 100, 500),
        (1, 100, 500),
        (100, 10, 100),
        (1_000, 3, 20),
    )
    results = []
    for count, python_iterations, native_iterations in cases:
        row = _measure_case(count, python_iterations, native_iterations)
        results.append(row)
        print(
            f"RUST-004 {count:5d} UTXO | "
            f"Python {row['python_reference']['median_ms_per_op']:10.4f} ms | "
            f"Rust prepared {row['rust_prepared_rows']['median_ms_per_op']:10.4f} ms "
            f"({row['speedup_prepared_rows']:8.2f}x) | "
            f"Rust e2e {row['rust_end_to_end']['median_ms_per_op']:10.4f} ms "
            f"({row['speedup_end_to_end']:8.2f}x)"
        )

    report = {
        "schema": "axven-rust-004-v1",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "native_boundary": axven_native.boundary_version(),
        "samples": SAMPLES,
        "note": "Shared-runner measurements are diagnostic only; correctness is checked before timing.",
        "production_consensus": "python",
        "results": results,
    }
    print("RUST-004-JSON " + json.dumps(report, sort_keys=True, separators=(",", ":")))
    print("RUST-004 native Sparse-Merkle benchmark: GREEN")


if __name__ == "__main__":
    main()
