#!/usr/bin/env python3
"""RUST-014: static policy for reproducibility-bound signed provenance."""
from __future__ import annotations

from pathlib import Path

import axven
import rust_011_portable_attestation as rust011
import rust_014_reproducible_attestation as att

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-reproducible-build.yml"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")
EXPECTED_INPUTS = {
    "native/axven_native/Cargo.toml",
    "native/axven_native/Cargo.lock",
    "native/axven_native/src/lib.rs",
    "requirements-native-build.lock",
    "requirements-ci-runtime-posix.lock",
    "rust_009_portable_linux_wheel_spec.py",
    "rust_013_reproducible_wheel_spec.py",
    "rust_013_reproducible_build_policy_spec.py",
    "rust_014_reproducible_attestation.py",
    "rust_014_reproducible_attestation_policy_spec.py",
    ".github/workflows/native-reproducible-build.yml",
}


def text(path: Path | str) -> str:
    target = path if isinstance(path, Path) else ROOT / path
    return target.read_text(encoding="utf-8")


def main() -> None:
    checks = 0
    workflow = text(WORKFLOW)
    source = text("rust_014_reproducible_attestation.py")
    doc = text("RUST_014.md")

    assert att.PROVENANCE_SCHEMA == "axven-native-reproducible-provenance-v1"
    assert att.ATTESTATION_SCHEMA == "axven-native-reproducible-attestation-envelope-v1"
    assert att.PAYLOAD_TYPE == "application/vnd.axven.native-reproducible-provenance.v1+json"
    assert att.ALGORITHM == "ed25519"
    assert att.KEY_ID == "rust-014-test-only-ed25519-v1"
    assert att.DOMAIN == b"AXVEN_NATIVE_REPRODUCIBLE_ATTESTATION_V1\x00"
    assert att.PINNED_PUBLIC_KEY.hex() == "530bca4775ffd53881935dc81738f6e4f37b1b9dcda1129fdbd7005692907c1a"
    assert att.KEY_ID != rust011.KEY_ID
    assert att.DOMAIN != rust011.DOMAIN
    assert att.PINNED_PUBLIC_KEY != rust011.PINNED_PUBLIC_KEY
    checks += 1
    print("[GREEN] RUST-014 has an independently pinned, domain-separated TEST-ONLY attestation policy")

    assert att.MANYLINUX_IMAGE == (
        "quay.io/pypa/manylinux_2_28_x86_64@"
        "sha256:443eabd378e140996780a772e12c1a1ef10551da933fe76d74a1bab61f68a7b7"
    )
    assert att.BUILDER_PYTHON == "3.13.13"
    assert att.RUST_VERSION == "1.98.0"
    assert att.MATURIN_VERSION == "1.15.0"
    assert att.PYO3_VERSION == "0.29.2"
    assert att.EXPECTED_WHEEL == "axven_native-0.1.0-cp313-abi3-manylinux_2_28_x86_64.whl"
    assert set(att.BUILD_INPUTS) == EXPECTED_INPUTS
    for marker in (
        '"source_date_epoch": epoch',
        '"build_count": 2',
        '"byte_identical": True',
        '"CARGO_INCREMENTAL": "0"',
        '"PYTHONHASHSEED": "0"',
        '"TZ": "UTC"',
        '"LC_ALL": "C.UTF-8"',
        "RUST-014 fail-closed mutation contract: 8/8 GREEN",
    ):
        assert marker in source, marker
    checks += 1
    print("[GREEN] provenance binds exact source epoch, builder/toolchain policy, two-build evidence, inputs, and 8/8 fail-closed tests")

    for marker in (
        '"RUST_014.md"',
        '"rust_014_reproducible_attestation.py"',
        '"rust_014_reproducible_attestation_policy_spec.py"',
    ):
        assert marker in workflow, marker
    assert "python rust_014_reproducible_attestation_policy_spec.py" in workflow
    assert "python rust_014_reproducible_attestation.py generate reproducible-provenance.json" in workflow
    assert "python rust_014_reproducible_attestation.py seal reproducible-provenance.json reproducible-attestation.json" in workflow
    assert "python rust_014_reproducible_attestation.py verify reproducible-provenance.json reproducible-attestation.json" in workflow
    assert "python rust_014_reproducible_attestation.py selftest reproducible-provenance.json reproducible-attestation.json" in workflow
    assert workflow.index("python rust_013_reproducible_wheel_spec.py") < workflow.index(
        "python rust_014_reproducible_attestation.py generate"
    )
    assert workflow.count("python rust_009_portable_linux_wheel_spec.py") == 2
    checks += 1
    print("[GREEN] workflow signs reproducibility evidence only after RUST-013 and both portable wheel contracts")

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
    assert "deliberately committed and test-only" in doc.lower()
    assert "does not upload either wheel" in doc.lower()
    checks += 1
    print("[GREEN] TEST-ONLY signed evidence adds no publication, OIDC, package, release, or deployment privilege")

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
    print("RUST-014 reproducibility attestation policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
