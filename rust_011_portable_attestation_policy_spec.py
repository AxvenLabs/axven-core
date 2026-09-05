#!/usr/bin/env python3
"""RUST-011: static contract for the portable attested native candidate gate."""
from __future__ import annotations

from pathlib import Path

import axven
import rust_011_portable_attestation as att

ROOT = Path(__file__).resolve().parent
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def main() -> None:
    checks = 0
    workflow = text(".github/workflows/native-portable-attestation.yml")
    doc = text("docs/history/rust/RUST_011.md")
    source = text("rust_011_portable_attestation.py")
    runtime_lock = text("requirements-ci-runtime-posix.lock")

    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert 'python-version: "3.13.15"' in workflow
    assert "platform.python_version() == '3.13.15'" in workflow
    assert 'platform.python_version() == \\"3.13.13\\"' in workflow
    assert att.HOST_PYTHON == "3.13.15"
    assert att.BUILDER_PYTHON == "3.13.13"
    assert "rustup toolchain install 1.98.0 --profile minimal" in workflow
    assert "requirements-native-build.lock" in workflow
    assert "requirements-ci-runtime-posix.lock" in workflow
    assert "${{ github.event.pull_request.head.sha || github.sha }}" in workflow
    assert att.MANYLINUX_IMAGE in workflow
    assert "docker image inspect" in workflow
    checks += 1
    print("[GREEN] source, host verifier, actual builder interpreter, toolchain, and immutable image are pinned")

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
        "docker push",
    )
    for marker in forbidden:
        assert marker not in lower, marker
    checks += 1
    print("[GREEN] no OIDC, publication, artifact upload, package/release write, or image push exists")

    assert att.PROVENANCE_SCHEMA == "axven-native-portable-provenance-v1"
    assert att.ATTESTATION_SCHEMA == "axven-native-portable-attestation-envelope-v1"
    assert att.ALGORITHM == "ed25519"
    assert att.KEY_ID == "rust-011-test-only-ed25519-v1"
    assert att.DOMAIN == b"AXVEN_NATIVE_PORTABLE_ATTESTATION_V1\x00"
    assert att.RUST_VERSION == "1.98.0"
    assert att.MATURIN_VERSION == "1.15.0"
    assert att.PYO3_VERSION == "0.29.2"
    assert att.PINNED_PUBLIC_KEY.hex() == "36868181c4f61de13030919ed7d03d6f517a7a1a9e15fde821579e09852c6722"
    assert "public_key" not in att.ENVELOPE_KEYS
    assert "TEST_SEED" in source
    assert '"python": BUILDER_PYTHON' in source
    assert "header_bytes = _canonical(header)" in source
    assert "+ header_bytes" in source
    assert "+ payload" in source
    assert "test-only" in doc.lower()
    assert "not production release authentication" in doc.lower()
    assert "builder and verifier python versions are intentionally distinguished" in doc.lower()
    assert "cryptography==50.0.1" in runtime_lock
    checks += 1
    print("[GREEN] truthful builder provenance and joint header/payload domain separation are locked")

    for command in (
        "python rust_009_portable_linux_wheel_spec.py",
        "python rust_011_portable_attestation.py generate portable-provenance.json",
        "python rust_011_portable_attestation.py seal portable-provenance.json portable-attestation.json",
        "python rust_011_portable_attestation.py verify portable-provenance.json portable-attestation.json",
        "python rust_011_portable_attestation.py selftest portable-provenance.json portable-attestation.json",
    ):
        assert command in workflow, command
    assert '.github/workflows/native-portable-attestation.yml' in att.BUILD_INPUTS
    assert "7/7 GREEN" in source
    checks += 1
    print("[GREEN] portable wheel evidence is generated, sealed, verified, and mutation-tested end to end")

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
    print("RUST-011 portable attestation policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
