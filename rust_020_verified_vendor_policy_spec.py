#!/usr/bin/env python3
"""RUST-020: static policy for verified offline Cargo vendor closure."""
from __future__ import annotations

from pathlib import Path

import axven
import rust_020_verified_vendor as vendor

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-verified-offline-vendor.yml"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")
FORBIDDEN_BUILDER = (
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
    builder = text("rust_020_verified_vendor.py")
    workflow = text(WORKFLOW)
    doc = text("RUST_020.md")

    assert vendor.CHECKSUM_FILENAME == ".cargo-checksum.json"
    assert vendor.VENDOR_CONTAINER_PATH == "/vendor"
    assert '[source.crates-io]\nreplace-with = "vendored-sources"' in vendor.CONFIG_TEXT
    assert '[source.vendored-sources]\ndirectory = "/vendor"' in vendor.CONFIG_TEXT
    assert '[net]\noffline = true' in vendor.CONFIG_TEXT
    for marker in (
        "dependency.verify_crates(cargo_lock, crate_dir)",
        "dependency._validate_crate_archive(archive_path)",
        "_write_checksum(package_dir, package_checksum)",
        "verify_vendor(cargo_lock, vendor_dir)",
        "RUST-020 verified Cargo vendor fail-closed contract: 8/8 GREEN",
    ):
        assert marker in builder, marker
    checks += 1
    print("[GREEN] RUST-020 vendor construction is rooted in the RUST-019 authenticated crate closure")

    for marker in FORBIDDEN_BUILDER:
        assert marker not in builder, marker
    for marker in (
        "path.is_symlink()",
        "not path.is_file()",
        "actual_names != set(expected_packages)",
        "metadata[\"package\"] != package_checksum",
        "set(metadata[\"files\"]) != set(actual_files)",
        "Cargo home must be empty before RUST-020 config creation",
    ):
        assert marker in builder, marker
    checks += 1
    print("[GREEN] vendor verifier is process/network independent and rejects filesystem/checksum mutations fail closed")

    for marker in (
        '"RUST_020.md"',
        '"rust_020_verified_vendor.py"',
        '"rust_020_verified_vendor_policy_spec.py"',
        '".github/workflows/native-verified-offline-vendor.yml"',
    ):
        assert workflow.count(marker) == 2, marker
    for marker in (
        "python rust_020_verified_vendor_policy_spec.py",
        "cargo fetch --locked --manifest-path native/axven_native/Cargo.toml",
        "python rust_019_offline_dependency_closure.py collect-crates",
        "python rust_019_offline_dependency_closure.py verify-crates",
        "python rust_020_verified_vendor.py build",
        "python rust_020_verified_vendor.py verify",
        "python rust_020_verified_vendor.py selftest",
        "python rust_020_verified_vendor.py write-config",
        "docker run --rm --network none",
        "CARGO_NET_OFFLINE=true",
        "cargo metadata --offline --locked",
        "-v \"$vendor_dir:/vendor:ro\"",
        "-v \"$cargo_home:/cargo-home\"",
        "-v \"$GITHUB_WORKSPACE/native/axven_native:/work/native/axven_native:ro\"",
    ):
        assert marker in workflow, marker
    build_at = workflow.index("Build verified RUST-020 Cargo vendor tree")
    verify_at = workflow.index("Verify RUST-020 Cargo vendor tree")
    selftest_at = workflow.index("RUST-020 vendor mutation contract")
    reverify_at = workflow.index("Reverify RUST-020 Cargo vendor tree")
    resolve_at = workflow.index("Resolve locked graph from verified vendor with network disabled")
    assert build_at < verify_at < selftest_at < reverify_at < resolve_at
    checks += 1
    print("[GREEN] workflow separates networked archive collection from verify -> mutate -> reverify -> network-disabled resolution")

    lower = workflow.lower()
    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "--network none" in workflow
    assert "CARGO_HOME=/cargo-home" in workflow
    assert "test ! -e \"$cargo_home/registry\"" in workflow
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
    assert "stops at dependency resolution" in doc.lower()
    checks += 1
    print("[GREEN] checkpoint adds no publication/signing/deployment privilege and keeps Cargo resolution offline")

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
    print("RUST-020 verified offline Cargo vendor policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
