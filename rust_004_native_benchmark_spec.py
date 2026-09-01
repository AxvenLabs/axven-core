#!/usr/bin/env python3
"""RUST-004: static contract for correctness-first native SMT benchmarking."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def main() -> None:
    checks = 0

    bench = text("rust_004_native_benchmark.py")
    workflow = text(".github/workflows/native-benchmark.yml")
    doc = text("RUST_004.md")
    cargo = text("native/axven_native/Cargo.toml")

    assert "SAMPLES = 5" in bench
    assert "_assert_root_shape" in bench
    assert 'assert native_root == python_root' in bench
    assert bench.index('assert native_root == python_root') < bench.index('python_result = _bench')
    for fixture in ("(0, 100, 500)", "(1, 100, 500)", "(100, 10, 100)", "(1_000, 3, 20)"):
        assert fixture in bench
    assert '"python_reference"' in bench
    assert '"rust_prepared_rows"' in bench
    assert '"rust_end_to_end"' in bench
    checks += 1
    print("[GREEN] correctness precedes timing and deterministic benchmark fixtures are fixed")

    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert 'python-version: "3.13.15"' in workflow
    assert "rustup toolchain install 1.98.0 --profile minimal" in workflow
    assert "cargo build --release --locked --manifest-path native/axven_native/Cargo.toml --features extension-module" in workflow
    assert "target/release/libaxven_native.so" in workflow
    assert "requirements-ci-runtime-posix.lock" in workflow
    checks += 1
    print("[GREEN] benchmark CI is read-only, hash-locked, and toolchain-pinned")

    assert 'pyo3 = { version = "=0.29.2"' in cargo
    assert 'sha2 = "=0.10.9"' in cargo
    assert 'default = []' in cargo
    assert 'extension-module = ["pyo3/extension-module"]' in cargo
    checks += 1
    print("[GREEN] RUST-004 introduces no new native dependency or default feature")

    for name in ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py"):
        assert "axven_native" not in text(name), name
    assert "benchmark-only" in doc.lower()
    assert "no minimum-speedup gate" in doc.lower()
    assert "production axven consensus continues to use `axven.smt_root_reference()`" in doc.lower()
    checks += 1
    print("[GREEN] production remains Python-only and benchmark results cannot alter semantics")

    assert 'axven.CHAIN_ID == "axven-devnet-2"' in bench
    assert 'axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"' in bench
    assert 'axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"' in bench
    assert 'axven.CHAIN_CONFIG["smt_activation_height"] == 10_000' in bench
    assert 'axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2_000' in bench
    assert 'axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5_000' in bench
    checks += 1
    print("[GREEN] canonical chain and activation identity are explicitly rechecked")

    assert checks == 5
    print("RUST-004 native benchmark contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
