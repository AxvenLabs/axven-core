#!/usr/bin/env python3
"""RUST-025: static policy for upstream-authenticated fully detached native rebuild."""
from __future__ import annotations

from pathlib import Path
import axven

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-upstream-authenticated-detached-rebuild.yml"
SCRIPT = ROOT / "rust_025_upstream_authenticated_detached_build.sh"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")

RUST_URL = "https://static.rust-lang.org/dist/2026-08-20/rust-1.98.0-x86_64-unknown-linux-gnu.tar.xz"
RUST_SHA256 = "ed8ee2df70909c88cbaf87a6cfa3920dac00b537de12a6abe6906641e0f5952f"
MANYLINUX = "quay.io/pypa/manylinux_2_28_x86_64@sha256:443eabd378e140996780a772e12c1a1ef10551da933fe76d74a1bab61f68a7b7"


def text(path: Path | str) -> str:
    target = path if isinstance(path, Path) else ROOT / path
    return target.read_text(encoding="utf-8")


def main() -> None:
    checks = 0
    workflow = text(WORKFLOW)
    script = text(SCRIPT)
    doc = text("RUST_025.md")

    for marker in (RUST_URL, RUST_SHA256, MANYLINUX, "permissions:\n  contents: read", "persist-credentials: false"):
        assert marker in workflow, marker
    assert "python rust_024_upstream_rust_distribution.py selftest" in workflow
    assert "python rust_025_upstream_authenticated_detached_build_policy_spec.py" in workflow
    checks += 1
    print("[GREEN] upstream Rust distribution, immutable builder and least-privilege workflow are pinned")

    upstream_at = script.index('python rust_024_upstream_rust_distribution.py verify-archive "$archive"')
    install_at = script.index("./install.sh --prefix=/install/1.98.0-x86_64-unknown-linux-gnu")
    closure_at = script.index("python rust_023_rust_toolchain_closure.py collect")
    source_at = script.index("python rust_018_detached_rebuild_verify.py sourcecheck")
    dependency_at = script.index("python rust_019_offline_dependency_closure.py verify")
    vendor_at = script.index("python rust_020_verified_vendor.py build")
    final_at = script.index("docker run --rm --network none", install_at + 1)
    verify_at = script.index("python rust_018_detached_rebuild_verify.py verify")
    assert upstream_at < install_at < closure_at < source_at < dependency_at < vendor_at < final_at < verify_at
    checks += 1
    print("[GREEN] upstream authentication, detached source and verified dependencies precede final build")

    final_block = script[final_at:verify_at]
    for marker in (
        '-v "$toolchain:/rust-toolchain:ro"',
        '-v "$rebuild_source/native/axven_native:/work/native/axven_native:ro"',
        '-v "$vendor_dir:/vendor:ro"',
        '-v "$bundle/python-wheels:/python-wheels:ro"',
        "CARGO_NET_OFFLINE=true",
        "RUSTFLAGS=--remap-path-prefix=/vendor=/axven/vendor",
        "python -m pip install --no-index --no-deps --no-cache-dir --target /tools /python-wheels/*.whl",
        "maturin build --release --locked",
        'test "$(rustc --version)" = "rustc 1.98.0 (88d9e12ae 2026-08-18)"',
        'test "$(cargo --version)" = "cargo 1.98.0 (797e8a9bc 2026-08-05)"',
        "test ! -e /cargo-home/registry/index",
        "test ! -e /cargo-home/registry/cache",
        "test ! -e /cargo-home/registry/src",
        "test ! -e /cargo-home/git",
    ):
        assert marker in final_block, marker
    for forbidden in (
        '$GITHUB_WORKSPACE',
        '-v "$HOME/.cargo:/cargo"',
        '-v "$HOME/.rustup:/rustup',
        '-v "$HOME/.cargo/bin',
        "cargo fetch",
        "pip download",
        "git ",
        "/github/workspace",
    ):
        assert forbidden not in final_block, forbidden
    assert 'if env | grep -q "^GITHUB_"' in final_block
    checks += 1
    print("[GREEN] final builder consumes only detached source, verified dependencies and authenticated Rust toolchain")

    for marker in (
        "python rust_018_detached_rebuild_verify.py verify",
        "python rust_018_detached_rebuild_verify.py selftest",
        "python rust_021_verified_dependency_rebuild_spec.py verify",
        "python rust_021_verified_dependency_rebuild_spec.py selftest",
        "python rust_013_reproducible_wheel_spec.py",
        "python rust_009_portable_linux_wheel_spec.py",
        "python rust_024_upstream_rust_distribution.py verify-archive",
        "python rust_023_rust_toolchain_closure.py verify",
    ):
        assert marker in script, marker
    checks += 1
    print("[GREEN] final wheel, dependency and Rust-toolchain trust are fail-closed and reverified")

    lower = workflow.lower() + "\n" + script.lower()
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
    assert "production consensus remains python-authoritative" in doc.lower()
    for name in PRODUCTION:
        assert "axven_native" not in text(name), name
    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    assert axven.CHAIN_CONFIG["smt_activation_height"] == 10_000
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2_000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5_000
    checks += 1
    print("[GREEN] no publication/routing privilege or canonical chain identity change is introduced")

    assert checks == 5
    print("RUST-025 upstream-authenticated detached build policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
