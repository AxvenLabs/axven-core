#!/usr/bin/env python3
"""RUST-018: static policy for authenticated, network-disabled detached rebuild."""
from __future__ import annotations

from pathlib import Path

import axven
import rust_014_reproducible_attestation as producer
import rust_018_detached_rebuild_verify as consumer

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-reproducible-build.yml"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")
EXPECTED_REBUILD_SOURCE = frozenset(
    {
        "native/axven_native/Cargo.toml",
        "native/axven_native/Cargo.lock",
        "native/axven_native/src/lib.rs",
        "native/axven_native/pyproject.toml",
        "native/axven_native/rust-toolchain.toml",
    }
)
EXPECTED_COMMIT_CONFIGS = frozenset(
    {
        "native/axven_native/pyproject.toml",
        "native/axven_native/rust-toolchain.toml",
    }
)
FORBIDDEN_CONSUMER = (
    "import os",
    "from os",
    "subprocess",
    "socket",
    "urllib",
    "requests",
    "http.client",
    "os.environ",
    "GITHUB_",
    "import axven",
    "from axven",
)


def text(path: Path | str) -> str:
    target = path if isinstance(path, Path) else ROOT / path
    return target.read_text(encoding="utf-8")


def main() -> None:
    checks = 0
    workflow = text(WORKFLOW)
    source = text("rust_018_detached_rebuild_verify.py")
    doc = text("RUST_018.md")
    native_pyproject = text("native/axven_native/pyproject.toml")
    rust_toolchain = text("native/axven_native/rust-toolchain.toml")

    assert consumer.REBUILD_SOURCE_KEYS == EXPECTED_REBUILD_SOURCE
    assert consumer.COMMIT_AUTHENTICATED_CONFIG_KEYS == EXPECTED_COMMIT_CONFIGS
    assert consumer.LEGACY_SIGNED_NATIVE_KEYS == EXPECTED_REBUILD_SOURCE - EXPECTED_COMMIT_CONFIGS
    assert EXPECTED_COMMIT_CONFIGS.isdisjoint(set(producer.BUILD_INPUTS))
    assert (EXPECTED_REBUILD_SOURCE - EXPECTED_COMMIT_CONFIGS).issubset(set(producer.BUILD_INPUTS))
    assert "[tool.maturin]" in native_pyproject
    assert 'bindings = "pyo3"' in native_pyproject
    assert 'features = ["extension-module"]' in native_pyproject
    assert 'channel = "1.98.0"' in rust_toolchain
    assert not (ROOT / ".cargo").exists()
    assert not (ROOT / "native" / ".cargo").exists()
    assert not (ROOT / "native" / "axven_native" / ".cargo").exists()
    assert not (ROOT / "Cargo.toml").exists()
    assert not (ROOT / "native" / "Cargo.toml").exists()
    checks += 1
    print("[GREEN] RUST-018 closes the two-file native config gap without inventing hidden Cargo/workspace inputs")

    for marker in FORBIDDEN_CONSUMER:
        assert marker not in source, marker
    assert source.index("sys.dont_write_bytecode = True") < source.index(
        "import rust_015_offline_repro_consumer_verify as evidence"
    )
    for marker in (
        "gitcheck._verify(",
        'gitcheck._git_oid("commit", commit_payload)',
        'gitcheck._git_oid("blob", path.read_bytes())',
        "rebuilt.read_bytes()" if False else "rebuilt_wheel.read_bytes()",
        "evidence._validate_wheel_zip(rebuilt_wheel",
        "RUST-018 detached source rebuild fail-closed contract: 8/8 GREEN",
    ):
        assert marker in source, marker
    checks += 1
    print("[GREEN] detached verifier composes signed evidence + Git membership + exact five-file source + rebuilt wheel equivalence")

    for marker in (
        '"RUST_018.md"',
        '"rust_018_detached_rebuild_verify.py"',
        '"rust_018_detached_rebuild_policy_spec.py"',
    ):
        assert workflow.count(marker) == 2, marker
    for marker in (
        "python rust_018_detached_rebuild_policy_spec.py",
        "Prepare authenticated RUST-018 rebuild source",
        "Authenticate detached RUST-018 rebuild source",
        "Stage RUST-018 offline build tools and Cargo cache",
        "Build RUST-018 detached source with network disabled",
        "Verify RUST-018 detached rebuild equivalence",
        "RUST-018 detached rebuild mutation contract",
        "Reverify RUST-018 detached rebuild equivalence",
        "--network none",
        "CARGO_NET_OFFLINE=true",
        'test ! -e "$rebuild_source/.git"',
        'test "$(find "$rebuild_source" -type f | wc -l)" -eq 5',
        "python rust_018_detached_rebuild_verify.py sourcecheck",
        "python rust_018_detached_rebuild_verify.py verify",
        "python rust_018_detached_rebuild_verify.py selftest",
    ):
        assert marker in workflow, marker
    sourcecheck_at = workflow.index("Authenticate detached RUST-018 rebuild source")
    build_at = workflow.index("Build RUST-018 detached source with network disabled")
    verify_at = workflow.index("Verify RUST-018 detached rebuild equivalence")
    assert sourcecheck_at < build_at < verify_at
    build_end = workflow.index("Verify RUST-018 detached rebuild equivalence")
    build_segment = workflow[build_at:build_end]
    assert 'GITHUB_WORKSPACE' not in build_segment
    assert '-v "$rebuild_source/native/axven_native:/src:ro"' in build_segment
    assert '-v "$rebuild_tools:/tools:ro"' in build_segment
    assert '-e CARGO_NET_OFFLINE=true' in build_segment
    assert "maturin build --release --locked --compatibility manylinux_2_28" in build_segment
    checks += 1
    print("[GREEN] rebuild occurs only after source authentication, with a read-only detached source mount and no network")

    lower = workflow.lower()
    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    for marker in (
        "id-token: write",
        "attestations: write",
        "packages: write",
        "contents: write",
        "actions/upload-artifact",
        "actions/attest",
        "maturin publish",
        "twine upload",
        "gh release",
        "softprops/action-gh-release",
        "docker push",
    ):
        assert marker not in lower, marker
    assert "does **not** publish artifacts" in doc.lower()
    assert "production consensus remains python-authoritative" in doc.lower()
    checks += 1
    print("[GREEN] source-closure hardening adds no publication, OIDC, signing, release, deployment, or routing privilege")

    for name in PRODUCTION:
        assert "axven_native" not in text(name), name
    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    assert axven.CHAIN_CONFIG["smt_activation_height"] == 10_000
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2_000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5_000
    checks += 1
    print("[GREEN] production remains Python-authoritative and canonical chain identity is unchanged")

    assert checks == 5
    print("RUST-018 detached rebuild policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
