#!/usr/bin/env python3
"""RUST-015: static policy for the detached reproducibility consumer."""
from __future__ import annotations

from pathlib import Path

import axven
import rust_014_reproducible_attestation as producer
import rust_015_offline_repro_consumer_verify as consumer

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
    source = text("rust_015_offline_repro_consumer_verify.py")
    doc = text("RUST_015.md")

    assert consumer.PROVENANCE_SCHEMA == producer.PROVENANCE_SCHEMA
    assert consumer.ATTESTATION_SCHEMA == producer.ATTESTATION_SCHEMA
    assert consumer.PAYLOAD_TYPE == producer.PAYLOAD_TYPE
    assert consumer.ALGORITHM == producer.ALGORITHM
    assert consumer.KEY_ID == producer.KEY_ID
    assert consumer.DOMAIN == producer.DOMAIN
    assert consumer.PINNED_PUBLIC_KEY == producer.PINNED_PUBLIC_KEY
    assert consumer.MANYLINUX_IMAGE == producer.MANYLINUX_IMAGE
    assert consumer.WHEEL_FILENAME == producer.EXPECTED_WHEEL
    assert consumer.BUILDER_POLICY["python"] == producer.BUILDER_PYTHON
    assert consumer.BUILDER_POLICY["rust"] == producer.RUST_VERSION
    assert consumer.BUILDER_POLICY["maturin"] == producer.MATURIN_VERSION
    assert consumer.BUILDER_POLICY["pyo3"] == producer.PYO3_VERSION
    assert set(consumer.BUILD_INPUT_KEYS) == set(producer.BUILD_INPUTS)
    checks += 1
    print("[GREEN] detached consumer independently pins the exact public RUST-014 policy")

    for marker in FORBIDDEN_CONSUMER_PATTERNS:
        assert marker not in source, marker
    for required in (
        "wheel_a.read_bytes() != wheel_b.read_bytes()",
        "_validate_wheel_zip(wheel_a, epoch)",
        "_validate_wheel_zip(wheel_b, epoch)",
        'value["build_count"] != 2',
        'value["byte_identical"] is not True',
        "RUST-015 detached reproducibility fail-closed contract: 13/13 GREEN",
    ):
        assert required in source, required
    checks += 1
    print("[GREEN] consumer has no repo/network/runtime dependency and recomputes two-wheel identity plus 13/13 mutations")

    for marker in (
        '"RUST_015.md"',
        '"rust_015_offline_repro_consumer_verify.py"',
        '"rust_015_offline_repro_consumer_policy_spec.py"',
    ):
        assert marker in workflow, marker
    for marker in (
        "python rust_015_offline_repro_consumer_policy_spec.py",
        "Prepare detached RUST-015 reproducibility bundle",
        'test ! -e "$consumer/.git"',
        'test "$(find "$consumer" -type f | wc -l)" -eq 5',
        "env -i",
        "python rust_015_offline_repro_consumer_verify.py verify",
        "python rust_015_offline_repro_consumer_verify.py selftest",
    ):
        assert marker in workflow, marker
    assert workflow.index("python rust_014_reproducible_attestation.py verify") < workflow.index(
        "Prepare detached RUST-015 reproducibility bundle"
    )
    checks += 1
    print("[GREEN] workflow creates an exact five-file detached tree only after RUST-014 verification and runs under env -i")

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
    assert "test-only" in doc.lower()
    assert "does not publish" in doc.lower()
    checks += 1
    print("[GREEN] detached rehearsal adds no publication, OIDC, signing, release, package, or deployment privilege")

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
    print("RUST-015 detached reproducibility consumer policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
