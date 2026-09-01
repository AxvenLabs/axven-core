#!/usr/bin/env python3
"""RUST-022: static policy for the fully detached source + dependency rebuild."""
from __future__ import annotations

from pathlib import Path

import axven

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-fully-detached-verified-rebuild.yml"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")
EXACT_SOURCE_FILES = (
    "native/axven_native/Cargo.toml",
    "native/axven_native/Cargo.lock",
    "native/axven_native/src/lib.rs",
    "native/axven_native/pyproject.toml",
    "native/axven_native/rust-toolchain.toml",
)


def text(path: Path | str) -> str:
    target = path if isinstance(path, Path) else ROOT / path
    return target.read_text(encoding="utf-8")


def main() -> None:
    checks = 0
    workflow = text(WORKFLOW)
    doc = text("RUST_022.md")

    for marker in (
        "python rust_018_detached_rebuild_verify.py sourcecheck",
        "python rust_018_detached_rebuild_verify.py verify",
        "python rust_018_detached_rebuild_verify.py selftest",
        "python rust_019_offline_dependency_closure.py verify",
        "python rust_019_offline_dependency_closure.py selftest",
        "python rust_020_verified_vendor.py verify",
        "python rust_020_verified_vendor.py selftest",
        "python rust_021_verified_dependency_rebuild_spec.py verify",
        "python rust_021_verified_dependency_rebuild_spec.py selftest",
        "python rust_013_reproducible_wheel_spec.py",
        "python rust_009_portable_linux_wheel_spec.py",
    ):
        assert marker in workflow, marker
    for relative in EXACT_SOURCE_FILES:
        assert relative in workflow, relative
    checks += 1
    print("[GREEN] RUST-022 composes existing authenticated source, dependency, vendor and wheel proofs")

    reference_at = workflow.index("Build RUST-022 reference candidates")
    evidence_at = workflow.index("Generate and seal RUST-014 reference evidence")
    source_at = workflow.index("Prepare authenticated RUST-022 detached source")
    sourcecheck_at = workflow.index("Authenticate RUST-022 detached source")
    collect_at = workflow.index("Collect RUST-022 authenticated dependency inputs")
    dependency_at = workflow.index("Verify RUST-019 dependency closure before final build")
    vendor_at = workflow.index("Build and verify RUST-020 vendor before final build")
    final_at = workflow.index("Build RUST-022 fully detached wheel with verified dependencies")
    verify_at = workflow.index("Verify RUST-022 fully detached rebuild equivalence")
    reverify_at = workflow.index("Reverify RUST-022 source and dependency closures after build")
    assert reference_at < evidence_at < source_at < sourcecheck_at < collect_at < dependency_at < vendor_at < final_at < verify_at < reverify_at
    checks += 1
    print("[GREEN] source and dependency trust are established before final build and reverified afterwards")

    final_block = workflow[final_at:verify_at]
    for marker in (
        "docker run --rm --network none",
        '-v "$rebuild_source/native/axven_native:/work/native/axven_native:ro"',
        '-v "$vendor_dir:/vendor:ro"',
        '-v "$bundle/python-wheels:/python-wheels:ro"',
        '-v "$cargo_home:/cargo-home"',
        '-v "$tools:/tools"',
        '-v "$output:/out"',
        '-v "$HOME/.cargo/bin:/cargo-bin:ro"',
        '-v "$HOME/.rustup:/rustup:ro"',
        "CARGO_NET_OFFLINE=true",
        "RUSTFLAGS=--remap-path-prefix=/vendor=/axven/vendor",
        "python -m pip install --no-index --no-deps --no-cache-dir --target /tools /python-wheels/*.whl",
        "maturin build --release --locked",
        "test ! -e /work/.git",
        "test ! -e /work/native/axven_native/.git",
        'test "$(find /work/native/axven_native -type f | wc -l)" -eq 5',
        "test ! -e /cargo-home/registry/index",
        "test ! -e /cargo-home/registry/cache",
        "test ! -e /cargo-home/registry/src",
        "test ! -e /cargo-home/git",
    ):
        assert marker in final_block, marker
    assert "if env | grep -q" in final_block and "GITHUB_" in final_block
    for forbidden in (
        '$GITHUB_WORKSPACE',
        '-v "$HOME/.cargo:/cargo"',
        "cargo fetch",
        "pip download",
        "git ",
        "/github/workspace",
        "reproducible-provenance.json",
        "reproducible-attestation.json",
    ):
        assert forbidden not in final_block, forbidden
    checks += 1
    print("[GREEN] final builder is repo-detached, GITHUB-env-clean, network-disabled and free of producer Cargo dependency caches")

    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    lower = workflow.lower()
    for forbidden in (
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
        assert forbidden not in lower, forbidden
    assert "does **not** upload or publish artifacts" in doc.lower()
    assert "production consensus remains python-authoritative" in doc.lower()
    checks += 1
    print("[GREEN] RUST-022 adds no publication, signing, deployment or production-routing privilege")

    for name in PRODUCTION:
        assert "axven_native" not in text(name), name
    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    assert axven.CHAIN_CONFIG["smt_activation_height"] == 10_000
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2_000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5_000
    checks += 1
    print("[GREEN] production Python authority and canonical chain identity remain unchanged")

    assert checks == 5
    print("RUST-022 fully detached verified rebuild policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
