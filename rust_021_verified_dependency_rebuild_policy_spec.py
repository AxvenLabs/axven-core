#!/usr/bin/env python3
"""RUST-021: static policy for verified dependency-consumed offline wheel rebuild."""
from __future__ import annotations

from pathlib import Path

import axven

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-verified-dependency-rebuild.yml"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")
FORBIDDEN_VERIFIER = (
    "import subprocess",
    "from subprocess",
    "import socket",
    "from socket",
    "urllib",
    "requests",
    "http.client",
    "os.environ",
    "GITHUB_",
    "import axven",
    "from axven",
    "docker",
)


def text(path: Path | str) -> str:
    target = path if isinstance(path, Path) else ROOT / path
    return target.read_text(encoding="utf-8")


def main() -> None:
    checks = 0
    workflow = text(WORKFLOW)
    verifier = text("rust_021_verified_dependency_rebuild_spec.py")
    doc = text("RUST_021.md")

    for marker in FORBIDDEN_VERIFIER:
        assert marker not in verifier, marker
    for marker in (
        "reference_hash != offline_hash",
        "reference.read_bytes() != offline.read_bytes()",
        "reference and offline wheel paths must be distinct",
        "RUST-021 dependency-consumed rebuild fail-closed contract: 6/6 GREEN",
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] RUST-021 verifier is process/network independent and requires exact wheel identity")

    for marker in (
        '"RUST_021.md"',
        '"rust_021_verified_dependency_rebuild_spec.py"',
        '"rust_021_verified_dependency_rebuild_policy_spec.py"',
        '".github/workflows/native-verified-dependency-rebuild.yml"',
    ):
        assert workflow.count(marker) == 2, marker
    for marker in (
        "Materialize canonical Cargo registry source root",
        "cargo metadata --locked --manifest-path native/axven_native/Cargo.toml",
        "python rust_019_offline_dependency_closure.py verify",
        "python rust_020_verified_vendor.py build",
        "python rust_020_verified_vendor.py verify",
        "python -m pip install --no-index --no-deps --no-cache-dir --target /tools /python-wheels/*.whl",
        "docker run --rm --network none",
        "CARGO_NET_OFFLINE=true",
        "maturin build --release --locked",
        "python rust_021_verified_dependency_rebuild_spec.py verify",
        "python rust_021_verified_dependency_rebuild_spec.py selftest",
        "python rust_013_reproducible_wheel_spec.py",
        "python rust_009_portable_linux_wheel_spec.py",
    ):
        assert marker in workflow, marker
    reference_at = workflow.index("Build RUST-021 reference wheel")
    verify_deps_at = workflow.index("Verify RUST-019 dependency inputs before consumption")
    vendor_at = workflow.index("Build and verify RUST-020 Cargo vendor tree")
    offline_at = workflow.index("Build RUST-021 wheel from verified dependencies with network disabled")
    identity_at = workflow.index("Verify RUST-021 offline wheel identity")
    mutation_at = workflow.index("RUST-021 wheel identity mutation contract")
    reapply_at = workflow.index("Reapply reproducible and portable wheel contracts")
    reverify_at = workflow.index("Reverify dependency inputs and vendor after build")
    assert reference_at < verify_deps_at < vendor_at < offline_at < identity_at < mutation_at < reapply_at < reverify_at
    checks += 1
    print("[GREEN] workflow authenticates dependencies before offline consumption and re-verifies them after wheel proof")

    for marker in (
        '-v "$vendor_dir:/vendor:ro"',
        '-v "$bundle/python-wheels:/python-wheels:ro"',
        '-v "$HOME/.rustup:/rustup:ro"',
        '-v "$GITHUB_WORKSPACE/native/axven_native:/work/native/axven_native:ro"',
        '-e REGISTRY_SOURCE_DIR="$REGISTRY_SOURCE_DIR"',
        'RUSTFLAGS="--remap-path-prefix=/cargo/registry/src/$REGISTRY_SOURCE_DIR=/axven/vendor"',
        "RUSTFLAGS=--remap-path-prefix=/vendor=/axven/vendor",
        "test \"$RUSTFLAGS\" = \"--remap-path-prefix=/vendor=/axven/vendor\"",
        "test ! -e /cargo-home/registry/index",
        "test ! -e /cargo-home/registry/cache",
        "test ! -e /cargo-home/registry/src",
        "test ! -e /cargo-home/git",
        "PIP_NO_CACHE_DIR=1",
        "--no-index",
    ):
        assert marker in workflow, marker
    assert 'case "${roots[0]}" in' in workflow
    assert "index.crates.io-*" in workflow
    assert 'test "${#roots[@]}" -eq 1' in workflow
    offline_block = workflow[workflow.index("Build RUST-021 wheel from verified dependencies with network disabled") :]
    assert '-v "$HOME/.cargo:/cargo"' not in offline_block
    assert "cargo fetch" not in offline_block
    assert "pip download" not in offline_block
    checks += 1
    print("[GREEN] dependency source paths are canonicalized while offline candidate keeps only verified vendor/Maturin inputs")

    lower = workflow.lower()
    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "--network none" in workflow
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
    print("[GREEN] checkpoint adds no publication/signing/deployment privilege and preserves Python production authority")

    for name in PRODUCTION:
        assert "axven_native" not in text(name), name
    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    assert axven.CHAIN_CONFIG["smt_activation_height"] == 10_000
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2_000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5_000
    checks += 1
    print("[GREEN] canonical chain identity and activation heights are unchanged")

    assert checks == 5
    print("RUST-021 verified dependency rebuild policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
