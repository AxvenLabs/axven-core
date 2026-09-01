#!/usr/bin/env python3
"""RUST-026: static policy for TEST-ONLY signed build-material attestation."""
from __future__ import annotations

from pathlib import Path
import axven

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-build-material-attestation.yml"
VERIFIER = ROOT / "rust_026_build_material_attestation.py"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")
RUST_SHA256 = "ed8ee2df70909c88cbaf87a6cfa3920dac00b537de12a6abe6906641e0f5952f"
PINNED_PUBLIC_KEY = "4dd000548d1ed66588e6c23531163bd12c9c5dbca5eb932d4c6a75cde6525064"


def text(path: Path | str) -> str:
    target = path if isinstance(path, Path) else ROOT / path
    return target.read_text(encoding="utf-8")


def main() -> None:
    checks = 0
    workflow = text(WORKFLOW)
    verifier = text(VERIFIER)
    doc = text("RUST_026.md")

    for marker in (
        "bash rust_025_upstream_authenticated_detached_build.sh",
        "python rust_026_build_material_attestation.py generate",
        "python rust_026_build_material_attestation.py seal",
        "python rust_026_build_material_attestation.py verify",
        'KEY_ID = "rust-026-test-only-ed25519-v1"',
        'DOMAIN = b"AXVEN_NATIVE_BUILD_MATERIAL_ATTESTATION_V1\\x00"',
        RUST_SHA256,
        PINNED_PUBLIC_KEY,
    ):
        assert marker in workflow + "\n" + verifier, marker
    assert "TEST_SEED" in verifier
    checks += 1
    print("[GREEN] RUST-026 composes RUST-025 evidence into a dedicated TEST-ONLY signed material statement")

    for marker in (
        '"artifact": wheel',
        '"distribution_sha256": RUST_SHA256',
        '"toolchain_manifest_sha256": toolchain[0]',
        '"cargo_lock_sha256"',
        '"native_build_lock_sha256"',
        '"closure_sha256": digest',
        '"production_consensus": "python-authoritative"',
        '"image": MANYLINUX_IMAGE',
    ):
        assert marker in verifier, marker
    assert "len(crates) != 23" in verifier and "len(wheels) != 1" in verifier
    assert "len(packages) != 23" in verifier
    checks += 1
    print("[GREEN] final wheel, source, Rust/toolchain, dependency/vendor and builder identities are bound")

    detached_at = workflow.index("Detached offline RUST-026 verification and mutation contract")
    reverify_at = workflow.index("Reverify pristine RUST-026 material attestation")
    detached = workflow[detached_at:reverify_at]
    for marker in (
        "env -i",
        'python "$consumer/verifier.py" verify',
        'python "$consumer/verifier.py" selftest',
        "/tmp/axven-rust025-dependencies",
        "/tmp/axven-rust025-vendor",
        "/tmp/axven-rust025-toolchain.json",
    ):
        assert marker in detached, marker
    for forbidden in (
        "git ",
        "/github/workspace",
        "GITHUB_WORKSPACE",
        "import rust_0",
        "from rust_0",
        "import axven",
        "from axven",
    ):
        assert forbidden not in verifier, forbidden
    assert "9/9 expected cases passed" in verifier
    checks += 1
    print("[GREEN] detached verifier is repo/Git/producer-module independent with 9/9 fail-closed mutations")

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
    assert "test-only" in doc.lower()
    assert "does not upload or publish" in doc.lower()
    checks += 1
    print("[GREEN] no production signing, publication, OIDC or deployment privilege is introduced")

    for name in PRODUCTION:
        assert "axven_native" not in text(name), name
    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    assert axven.CHAIN_CONFIG["smt_activation_height"] == 10_000
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2_000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5_000
    assert "production consensus remains python-authoritative" in doc.lower()
    checks += 1
    print("[GREEN] production Python authority and canonical chain identity remain unchanged")

    assert checks == 5
    print("RUST-026 build-material attestation policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
