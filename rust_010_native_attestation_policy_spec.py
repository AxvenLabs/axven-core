#!/usr/bin/env python3
"""RUST-010: static contract for the offline test-only native attestation envelope."""
from __future__ import annotations

from pathlib import Path

import axven
import rust_010_native_attestation as att

ROOT = Path(__file__).resolve().parent
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def main() -> None:
    checks = 0
    workflow = text(".github/workflows/native-attestation-envelope.yml")
    doc = text("RUST_010.md")
    source = text("rust_010_native_attestation.py")

    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert 'python-version: "3.13.15"' in workflow
    assert "rustup toolchain install 1.98.0 --profile minimal" in workflow
    assert "requirements-native-build.lock" in workflow
    assert "requirements-ci-runtime-posix.lock" in workflow
    assert "${{ github.event.pull_request.head.sha || github.sha }}" in workflow
    checks += 1
    print("[GREEN] attestation CI identity/toolchain inputs are pinned and read-only")

    lower = workflow.lower()
    forbidden = (
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
    )
    for marker in forbidden:
        assert marker not in lower, marker
    checks += 1
    print("[GREEN] no OIDC, attestation publication, artifact upload, package publish, or release write exists")

    assert att.ATTESTATION_SCHEMA == "axven-native-attestation-envelope-v1"
    assert att.PROVENANCE_SCHEMA == "axven-native-artifact-provenance-v1"
    assert att.ALGORITHM == "ed25519"
    assert att.KEY_ID == "rust-010-test-only-ed25519-v1"
    assert att.DOMAIN == b"AXVEN_NATIVE_ATTESTATION_V1\x00"
    assert att.PINNED_PUBLIC_KEY.hex() == "7569ab4f72cba7d82e48b43d91ad964a73d5d498a1df6e75271fc92bf57cb54e"
    assert "public_key" not in att.ENVELOPE_KEYS
    assert "TEST_SEED" in source
    assert "test-only" in doc.lower()
    assert "not a production authentication mechanism" in doc.lower()
    checks += 1
    print("[GREEN] verifier uses a pinned external test trust root and explicit domain separation")

    for command in (
        "rust_008_native_provenance.py generate native-provenance.json",
        "rust_008_native_provenance.py verify native-provenance.json",
        "rust_010_native_attestation.py seal native-provenance.json native-attestation.json",
        "rust_010_native_attestation.py verify native-provenance.json native-attestation.json",
        "rust_010_native_attestation.py selftest native-provenance.json native-attestation.json",
    ):
        assert command in workflow, command
    assert "6/6 GREEN" in source
    checks += 1
    print("[GREEN] canonical provenance is sealed, reverified, and exercised against fail-closed mutations")

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
    print("RUST-010 offline attestation policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
