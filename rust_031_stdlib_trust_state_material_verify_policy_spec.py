#!/usr/bin/env python3
"""RUST-031: static policy for stdlib successor verification behind a monotonic trust floor."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import axven

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-stdlib-monotonic-trust-consumer.yml"
VERIFIER = ROOT / "rust_031_stdlib_trust_state_material_verify.py"
BASE = ROOT / "rust_030_stdlib_material_verify.py"
DOC = ROOT / "RUST_031.md"
EXPECTED_RUST030_GIT_BLOB = "0688cac21315533a3ff0fd760d28a44a9c897a6f"
ALLOWED_IMPORTS = {"__future__", "base64", "copy", "hashlib", "json", "pathlib", "sys", "tempfile", "rust_030_stdlib_material_verify"}
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")


def text(path: Path | str) -> str:
    target = path if isinstance(path, Path) else ROOT / path
    return target.read_text(encoding="utf-8")


def imported_roots(source: str) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def git_blob_sha(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()


def main() -> None:
    checks = 0
    verifier = text(VERIFIER)
    workflow = text(WORKFLOW)
    doc = text(DOC)
    base_raw = BASE.read_bytes()

    assert git_blob_sha(base_raw) == EXPECTED_RUST030_GIT_BLOB
    assert "does not introduce another ed25519 implementation" in doc.lower()
    assert "import rust_030_stdlib_material_verify as material_verify" in verifier
    checks += 1
    print("[GREEN] RUST-031 reuses the byte-identical reviewed RUST-030 stdlib Ed25519 implementation")

    roots = imported_roots(verifier)
    assert roots <= ALLOWED_IMPORTS, roots - ALLOWED_IMPORTS
    for forbidden in (
        "cryptography",
        "nacl",
        "OpenSSL",
        "Ed25519PrivateKey",
        "TEST_SEED",
        "def seal",
        "def issue",
        "subprocess",
        "import axven",
        "from axven",
        "requests",
        "urllib",
        "socket",
    ):
        assert forbidden not in verifier, forbidden
    checks += 1
    print("[GREEN] RUST-031 detached consumer is stdlib-only plus the pinned RUST-030 verifier and has no signing/network capability")

    for marker in (
        'NEW_KEY_ID = "rust-028-test-only-ed25519-v2"',
        'NEW_PUBLIC_KEY = bytes.fromhex("158d55a155c9191d0783d48c1a1a1531fe65a783356c5b221e6952e57d58fdb3")',
        "MINIMUM_SEQUENCE = 1",
        "validate_transition(transition_raw, transition, transition_envelope, expected_source_sha)",
        "validate_final_state(final_raw, final_state, genesis_raw, transition_raw, expected_source_sha)",
        'verify_ed25519(bytes.fromhex(final_state["public_key"]), new_envelope["signature"]',
        "old_envelope[\"payload_sha256\"] != new_envelope[\"payload_sha256\"]",
        "11/11 expected cases passed",
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] successor acceptance is chained through sequence-1 state and the RUST-029 rollback floor")

    for marker in (
        "python rust_031_stdlib_trust_state_material_verify_policy_spec.py",
        "python rust_030_stdlib_material_verify_policy_spec.py",
        "python rust_029_monotonic_trust_state_policy_spec.py",
        "bash rust_025_upstream_authenticated_detached_build.sh",
        "python rust_026_build_material_attestation.py generate",
        "python rust_026_build_material_attestation.py seal",
        "Issue RUST-028/RUST-029 TEST-ONLY successor evidence",
        "Detached RUST-031 stdlib monotonic trust consumer",
        "/usr/bin/python3 -S",
        "env -i",
        "PYTHONNOUSERSITE=1",
        "rust_031_stdlib_trust_state_material_verify.py",
        "rust_030_stdlib_material_verify.py",
    ):
        assert marker in workflow, marker
    checks += 1
    print("[GREEN] workflow composes real RUST-025/026 material evidence with RUST-028/029 TEST-ONLY trust evidence")

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
    assert "does not add a production signing key" in doc.lower()
    checks += 1
    print("[GREEN] RUST-031 adds no publication, OIDC, production signing, release or deployment privilege")

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

    assert checks == 6
    print("RUST-031 stdlib monotonic trust consumer policy contract: 6/6 GREEN")


if __name__ == "__main__":
    main()
