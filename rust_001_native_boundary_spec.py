#!/usr/bin/env python3
"""RUST-001: dormant deterministic axven_native boundary contract."""
from __future__ import annotations

from pathlib import Path
import tomllib

import axven

ROOT = Path(__file__).resolve().parent
NATIVE = ROOT / "native" / "axven_native"


def main() -> None:
    checks = 0

    cargo = tomllib.loads((NATIVE / "Cargo.toml").read_text(encoding="utf-8"))
    pyo3 = cargo["dependencies"]["pyo3"]
    assert pyo3["version"] == "=0.29.2"
    assert "abi3-py313" in pyo3["features"]
    assert cargo["features"]["default"] == []
    assert cargo["features"]["extension-module"] == ["pyo3/extension-module"]
    checks += 1
    print("[GREEN] PyO3 dependency and extension feature are exactly pinned")

    lock = tomllib.loads((NATIVE / "Cargo.lock").read_text(encoding="utf-8"))
    packages = {(pkg["name"], pkg["version"]): pkg for pkg in lock["package"]}
    assert ("pyo3", "0.29.2") in packages
    assert ("pyo3-build-config", "0.29.2") in packages
    assert ("pyo3-ffi", "0.29.2") in packages
    assert ("pyo3-macros", "0.29.2") in packages
    for name in ("pyo3", "pyo3-build-config", "pyo3-ffi", "pyo3-macros"):
        assert packages[(name, "0.29.2")].get("checksum")
    checks += 1
    print("[GREEN] Cargo.lock freezes the PyO3 0.29.2 dependency graph with registry checksums")

    pyproject = tomllib.loads((NATIVE / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["build-system"]["requires"] == ["maturin==1.15.0"]
    assert pyproject["project"]["requires-python"] == ">=3.13.15,<3.14"
    assert pyproject["tool"]["maturin"]["module-name"] == "axven_native"
    assert pyproject["tool"]["maturin"]["features"] == ["extension-module"]
    checks += 1
    print("[GREEN] maturin and Python ABI boundary are exactly pinned")

    toolchain = tomllib.loads((NATIVE / "rust-toolchain.toml").read_text(encoding="utf-8"))
    assert toolchain["toolchain"]["channel"] == "1.98.0"
    assert toolchain["toolchain"]["profile"] == "minimal"
    assert set(toolchain["toolchain"]["components"]) == {"clippy", "rustfmt"}
    checks += 1
    print("[GREEN] native crate pins the reviewed Rust toolchain")

    source = (NATIVE / "src" / "lib.rs").read_text(encoding="utf-8")
    assert "#[pymodule]" in source
    assert "fn native_probe" in source
    assert "fn boundary_version" in source
    forbidden = (
        "unsafe ",
        "std::fs",
        "std::net",
        "std::env",
        "std::time",
        "std::process",
        "std::thread",
        "rand::",
        "getrandom",
    )
    for token in forbidden:
        assert token not in source, token
    checks += 1
    print("[GREEN] RUST-001 FFI probe is deterministic and side-effect free by construction")

    for name in ("axven.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py", "core.py"):
        production = (ROOT / name).read_text(encoding="utf-8")
        assert "axven_native" not in production, name
    checks += 1
    print("[GREEN] production Axven code does not route through the native module")

    audited_native_files = (
        NATIVE / "Cargo.toml",
        NATIVE / "pyproject.toml",
        NATIVE / "rust-toolchain.toml",
        NATIVE / "README.md",
        NATIVE / "src" / "lib.rs",
    )
    all_native_text = "\n".join(
        path.read_text(encoding="utf-8", errors="strict")
        for path in audited_native_files
    )
    assert "ML-KEM" not in all_native_text
    assert "mldsa" not in source.lower()
    assert "ed25519" not in source.lower()
    checks += 1
    print("[GREEN] RUST-001 does not reimplement or extend cryptographic primitives")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    assert axven.CHAIN_CONFIG["smt_activation_height"] == 10_000
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2_000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5_000
    checks += 1
    print("[GREEN] RUST-001 leaves canonical chain and PQ activation identity unchanged")

    assert checks == 8, checks
    print("RUST-001 native boundary skeleton: 8/8 GREEN")


if __name__ == "__main__":
    main()
