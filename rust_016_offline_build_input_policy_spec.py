#!/usr/bin/env python3
"""RUST-016: static policy for detached signed build-input verification."""
from __future__ import annotations

from pathlib import Path

import axven
import rust_014_reproducible_attestation as producer
import rust_015_offline_repro_consumer_verify as upstream
import rust_016_offline_build_input_verify as consumer

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-reproducible-build.yml"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")
FORBIDDEN_CONSUMER_PATTERNS = (
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
    "import rust_014_reproducible_attestation",
    "from rust_014_reproducible_attestation",
    "docker ",
)


def text(path: Path | str) -> str:
    target = path if isinstance(path, Path) else ROOT / path
    return target.read_text(encoding="utf-8")


def main() -> None:
    checks = 0
    workflow = text(WORKFLOW)
    source = text("rust_016_offline_build_input_verify.py")
    doc = text("RUST_016.md")

    assert consumer.BUILD_INPUT_KEYS == upstream.BUILD_INPUT_KEYS
    assert consumer.BUILD_INPUT_KEYS == frozenset(producer.BUILD_INPUTS)
    assert upstream.PROVENANCE_SCHEMA == producer.PROVENANCE_SCHEMA
    assert upstream.ATTESTATION_SCHEMA == producer.ATTESTATION_SCHEMA
    assert upstream.PINNED_PUBLIC_KEY == producer.PINNED_PUBLIC_KEY
    assert upstream.MANYLINUX_IMAGE == producer.MANYLINUX_IMAGE
    assert upstream.WHEEL_FILENAME == producer.EXPECTED_WHEEL
    checks += 1
    print("[GREEN] RUST-016 composes with RUST-015 and pins the exact signed RUST-014 build-input set")

    for marker in FORBIDDEN_CONSUMER_PATTERNS:
        assert marker not in source, marker
    for required in (
        "import rust_015_offline_repro_consumer_verify as upstream",
        'source_root.rglob("*")',
        "entry.is_symlink()",
        "seen_files != set(BUILD_INPUT_KEYS)",
        'digest != claims[name]',
        "upstream._verify(",
        "RUST-016 detached signed build-input fail-closed contract: 8/8 GREEN",
    ):
        assert required in source, required
    checks += 1
    print("[GREEN] detached verifier is offline, symlink/path strict, hash-recomputing, and fail-closed 8/8")

    for marker in (
        '"RUST_016.md"',
        '"rust_016_offline_build_input_verify.py"',
        '"rust_016_offline_build_input_policy_spec.py"',
    ):
        assert marker in workflow, marker
    for marker in (
        "python rust_016_offline_build_input_policy_spec.py",
        "Prepare detached RUST-016 build-input bundle",
        'test ! -e "$consumer/.git"',
        'test "$(find "$consumer" -type f | wc -l)" -eq 17',
        'test "$(find "$consumer/source-inputs" -type f | wc -l)" -eq 11',
        "cp rust_015_offline_repro_consumer_verify.py",
        "cp rust_016_offline_build_input_verify.py",
        "env -i",
        "python rust_016_offline_build_input_verify.py verify",
        "python rust_016_offline_build_input_verify.py selftest",
    ):
        assert marker in workflow, marker
    assert workflow.index("Reverify detached RUST-015 evidence") < workflow.index(
        "Prepare detached RUST-016 build-input bundle"
    )
    checks += 1
    print("[GREEN] workflow builds an exact detached 17-file/11-input bundle after RUST-015 verification")

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
    assert "does not publish" in doc.lower()
    assert "does **not** claim" in doc.lower()
    checks += 1
    print("[GREEN] source-content proof is scoped honestly and adds no publish/OIDC/signing/deployment privilege")

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
    print("RUST-016 detached signed build-input policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
