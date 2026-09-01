#!/usr/bin/env python3
"""RUST-028: static policy for TEST-ONLY attestation trust-root rotation continuity."""
from __future__ import annotations

from pathlib import Path

import axven

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-trust-root-rotation.yml"
VERIFIER = ROOT / "rust_028_trust_root_rotation_verify.py"
DOC = ROOT / "RUST_028.md"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")
OLD_KEY_ID = "rust-026-test-only-ed25519-v1"
OLD_PUBLIC_KEY = "4dd000548d1ed66588e6c23531163bd12c9c5dbca5eb932d4c6a75cde6525064"
NEW_KEY_ID = "rust-028-test-only-ed25519-v2"
NEW_PUBLIC_KEY = "158d55a155c9191d0783d48c1a1a1531fe65a783356c5b221e6952e57d58fdb3"


def text(path: Path | str) -> str:
    target = path if isinstance(path, Path) else ROOT / path
    return target.read_text(encoding="utf-8")


def main() -> None:
    checks = 0
    workflow = text(WORKFLOW)
    verifier = text(VERIFIER)
    doc = text(DOC)

    for marker in (
        OLD_KEY_ID,
        OLD_PUBLIC_KEY,
        NEW_KEY_ID,
        NEW_PUBLIC_KEY,
        "axven-native-trust-transition-v1",
        "axven-native-trust-transition-envelope-v1",
        "AXVEN_NATIVE_TRUST_TRANSITION_V1",
        "sequence",
        "activation_source_commit",
        '"production": False',
        "RUST-028 trust-root rotation fail-closed contract: 10/10 expected cases passed",
    ):
        assert marker in verifier or marker in workflow, marker
    assert OLD_PUBLIC_KEY != NEW_PUBLIC_KEY
    checks += 1
    print("[GREEN] old/new TEST-ONLY trust roots and transition policy are independently pinned")

    for forbidden in (
        "TEST_SEED",
        "Ed25519PrivateKey",
        "def seal",
        "def issue",
        "import rust_026",
        "from rust_026",
        "import axven",
        "subprocess",
        "git ",
    ):
        assert forbidden not in verifier, forbidden
    assert "Ed25519PublicKey" in verifier
    assert "verify_signature" in verifier
    checks += 1
    print("[GREEN] detached RUST-028 consumer is verification-only and contains no private signing capability")

    for marker in (
        "bash rust_025_upstream_authenticated_detached_build.sh",
        "cp rust_027_offline_material_verify.py",
        "python rust_026_build_material_attestation.py generate",
        "python rust_026_build_material_attestation.py seal",
        "Issue RUST-028 TEST-ONLY trust transition",
        "Detached RUST-028 trust-root rotation consumer",
        "env -i",
        "python \"$consumer/verifier.py\" verify",
        "python \"$consumer/verifier.py\" selftest",
    ):
        assert marker in workflow, marker
    old_verify = workflow.index("Verify RUST-027 material evidence before rotation")
    issue = workflow.index("Issue RUST-028 TEST-ONLY trust transition")
    detached = workflow.index("Detached RUST-028 trust-root rotation consumer")
    reverify = workflow.index("Reverify pristine RUST-028 rotation result")
    assert old_verify < issue < detached < reverify
    checks += 1
    print("[GREEN] real build-material evidence is verified before old-signed rotation and detached successor verification")

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
        "docker push",
    ):
        assert forbidden not in lower, forbidden
    assert "test-only" in doc.lower()
    assert "production consensus remains python-authoritative" in doc.lower()
    checks += 1
    print("[GREEN] RUST-028 adds no publication, OIDC, production-signing or deployment privilege")

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
    print("RUST-028 TEST-ONLY trust-root rotation policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
