#!/usr/bin/env python3
"""RUST-003: static contract for bounded test-only native SMT fuzzing."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def main() -> None:
    checks = 0

    cargo = text("native/axven_native/Cargo.toml")
    fuzz_cargo = text("native/axven_native/fuzz/Cargo.toml")
    lock = text("native/axven_native/fuzz/Cargo.lock")
    workflow = text(".github/workflows/native-fuzz.yml")
    source = text("native/axven_native/src/lib.rs")
    target = text("native/axven_native/fuzz/fuzz_targets/smt_mirror.rs")
    doc = text("RUST_003.md")

    assert 'fuzzing = []' in cargo
    assert 'features = ["fuzzing"]' in fuzz_cargo
    assert 'libfuzzer-sys = "=0.4.13"' in fuzz_cargo
    assert 'name = "libfuzzer-sys"\nversion = "0.4.13"' in lock
    assert 'name = "pyo3"\nversion = "0.29.2"' in lock
    assert 'name = "sha2"\nversion = "0.10.9"' in lock
    checks += 1
    print("[GREEN] native fuzz feature and dependency graph are exact and locked")

    assert "permissions:\n  contents: read" in workflow
    assert "nightly-2026-08-20" in workflow
    assert "cargo-fuzz --version 0.13.2 --locked" in workflow
    assert "-runs=20000" in workflow
    assert "-max_len=4096" in workflow
    assert "-timeout=5" in workflow
    assert "-rss_limit_mb=1024" in workflow
    checks += 1
    print("[GREEN] native fuzz CI is read-only, pinned, and resource bounded")

    assert 'const MAX_INPUT_BYTES: usize = 4096;' in target
    assert 'const MAX_RECORDS: usize = 32;' in target
    assert 'const MAX_TEXT_BYTES: usize = 96;' in target
    assert "assert_eq!(baseline, fuzz_smt_root_mirror(&records));" in target
    assert "reversed.reverse();" in target
    assert "rotated.rotate_left(shift);" in target
    checks += 1
    print("[GREEN] fuzz decoding and metamorphic invariants are explicitly bounded")

    assert '#[cfg(feature = "fuzzing")]' in source
    assert "pub struct FuzzUtxoRecord" in source
    assert "pub fn fuzz_smt_root_mirror" in source
    for name in ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py"):
        assert "axven_native" not in text(name), name
    checks += 1
    print("[GREEN] fuzz hook is feature-gated and production remains Python-only")

    axven_source = text("axven.py")
    assert '"chain_id":"axven-devnet-2"' in axven_source
    assert '"smt_activation_height":10000' in axven_source
    assert '"pq_hybrid_activation_height":2000' in axven_source
    assert '"pq_pure_activation_height":5000' in axven_source
    assert "production consensus continues to use the Python state-root oracle" in doc
    checks += 1
    print("[GREEN] RUST-003 leaves canonical chain and activation identity unchanged")

    assert checks == 5
    print("RUST-003 native fuzz contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
