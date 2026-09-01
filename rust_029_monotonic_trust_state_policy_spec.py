#!/usr/bin/env python3
"""RUST-029: static policy for monotonic TEST-ONLY trust-state rollback defense."""
from __future__ import annotations

from pathlib import Path

import axven

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-monotonic-trust-state.yml"
VERIFIER = ROOT / "rust_029_monotonic_trust_state.py"
DOC = ROOT / "RUST_029.md"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")
OLD_KEY_ID = "rust-026-test-only-ed25519-v1"
NEW_KEY_ID = "rust-028-test-only-ed25519-v2"


def text(path: Path | str) -> str:
    target = path if isinstance(path, Path) else ROOT / path
    return target.read_text(encoding="utf-8")


def main() -> None:
    checks = 0
    workflow = text(WORKFLOW)
    verifier = text(VERIFIER)
    doc = text(DOC)

    for marker in (
        "axven-native-trust-state-v1",
        "MINIMUM_SEQUENCE = 1",
        OLD_KEY_ID,
        NEW_KEY_ID,
        "predecessor_sha256",
        "transition_sha256",
        "non-monotonic transition/replay rejected",
        "stale trust state below minimum sequence",
        "RUST-029 monotonic trust-state fail-closed contract: 10/10 expected cases passed",
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] RUST-029 pins sequence-1 trust floor and hash-linked trust-state continuity")

    for forbidden in (
        "TEST_SEED",
        "Ed25519PrivateKey",
        "def seal",
        "def issue",
        "import axven",
        "subprocess",
        "git ",
        "requests",
        "urllib",
        "socket",
    ):
        assert forbidden not in verifier, forbidden
    assert "Ed25519PublicKey" in verifier
    assert "derive_next" in verifier and "enforce_floor" in verifier
    checks += 1
    print("[GREEN] detached trust-state machine is verification-only and network/Git/producer independent")

    for marker in (
        "RUST-029 static monotonic trust-state policy",
        "Issue RUST-029 sequence-1 TEST-ONLY transition fixture",
        "Detached RUST-029 monotonic trust-state consumer",
        "python \"$consumer/verifier.py\" advance",
        "python \"$consumer/verifier.py\" verify",
        "python \"$consumer/verifier.py\" selftest",
        "env -i",
        "test ! -e \"$consumer/.git\"",
        "sequence\": 0",
        "sequence\": 1",
    ):
        assert marker in workflow, marker
    issue_at = workflow.index("Issue RUST-029 sequence-1 TEST-ONLY transition fixture")
    detached_at = workflow.index("Detached RUST-029 monotonic trust-state consumer")
    reverify_at = workflow.index("Reverify pristine RUST-029 trust state")
    assert issue_at < detached_at < reverify_at
    checks += 1
    print("[GREEN] old-authorized transition is applied once, detached, then reverified at the monotonic floor")

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
    assert "does **not** claim" in doc.lower()
    assert "production consensus remains python-authoritative" in doc.lower()
    checks += 1
    print("[GREEN] rollback claims are bounded and no publication/production-signing privilege is introduced")

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
    print("RUST-029 monotonic TEST-ONLY trust-state policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
