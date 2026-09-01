#!/usr/bin/env python3
"""RUST-030: static policy for the stdlib-only detached monotonic trust consumer."""
from __future__ import annotations

import ast
from pathlib import Path

import axven
import rust_030_stdlib_monotonic_trust_verify as consumer

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-stdlib-monotonic-trust.yml"
CONSUMER = ROOT / "rust_030_stdlib_monotonic_trust_verify.py"
DOC = ROOT / "RUST_030.md"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")

EXPECTED_OLD_KEY = "4dd000548d1ed66588e6c23531163bd12c9c5dbca5eb932d4c6a75cde6525064"
EXPECTED_NEW_KEY = "158d55a155c9191d0783d48c1a1a1531fe65a783356c5b221e6952e57d58fdb3"
ALLOWED_STDLIB_IMPORTS = {
    "__future__",
    "base64",
    "binascii",
    "copy",
    "hashlib",
    "json",
    "pathlib",
    "sys",
    "tempfile",
}


def text(path: Path | str) -> str:
    target = path if isinstance(path, Path) else ROOT / path
    return target.read_text(encoding="utf-8")


def imported_roots(source: str) -> set[str]:
    tree = ast.parse(source)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def main() -> None:
    checks = 0
    source = text(CONSUMER)
    workflow = text(WORKFLOW)
    doc = text(DOC)

    assert imported_roots(source) <= ALLOWED_STDLIB_IMPORTS
    for forbidden in (
        "cryptography",
        "Ed25519PrivateKey",
        "TEST_SEED",
        "subprocess",
        "socket",
        "urllib",
        "requests",
        "http.client",
        "os.environ",
        "GITHUB_",
        "import axven",
    ):
        assert forbidden not in source, forbidden
    assert "def advance(" not in source
    assert "rfc8032_selftest" in source
    assert "_require_prime_subgroup" in source
    assert "hashlib.sha512" in source
    assert "GROUP_L" in source
    checks += 1
    print("[GREEN] detached RUST-030 consumer is stdlib-only and verification-only")

    assert consumer.OLD_PUBLIC_KEY.hex() == EXPECTED_OLD_KEY
    assert consumer.NEW_PUBLIC_KEY.hex() == EXPECTED_NEW_KEY
    assert consumer.OLD_KEY_ID == "rust-026-test-only-ed25519-v1"
    assert consumer.NEW_KEY_ID == "rust-028-test-only-ed25519-v2"
    assert consumer.MINIMUM_SEQUENCE == 1
    assert consumer.TRANSITION_DOMAIN == b"AXVEN_NATIVE_TRUST_TRANSITION_V1\x00"
    assert consumer.MATERIAL_PAYLOAD_TYPE == "application/vnd.axven.native-build-materials.v1+json"
    consumer.rfc8032_selftest()
    checks += 1
    print("[GREEN] RFC 8032 verification and sequence-1 TEST-ONLY trust pins are fixed")

    for marker in (
        "python rust_029_monotonic_trust_state.py verify",
        "python rust_029_monotonic_trust_state.py selftest",
        "Stage exact detached RUST-030 consumer",
        'test "$(find "$consumer" -maxdepth 1 -type f | wc -l)" -eq 5',
        'test "$(find "$consumer" -type l | wc -l)" -eq 0',
        "/usr/bin/python3 -S rust_030_stdlib_monotonic_trust_verify.py verify",
        "/usr/bin/python3 -S rust_030_stdlib_monotonic_trust_verify.py selftest",
        'assert importlib.util.find_spec("cryptography") is None',
        "PYTHONNOUSERSITE=1",
    ):
        assert marker in workflow, marker
    differential_at = workflow.index("Differentially verify fixture with RUST-029")
    stage_at = workflow.index("Stage exact detached RUST-030 consumer")
    detached_at = workflow.index("Verify detached RUST-030 trust chain with stdlib only")
    mutation_at = workflow.index("RUST-030 detached stdlib fail-closed contract")
    reverify_at = workflow.index("Reverify pristine detached RUST-030 trust chain")
    assert differential_at < stage_at < detached_at < mutation_at < reverify_at
    detached_block = workflow[detached_at:reverify_at]
    assert "env -i" in detached_block
    assert "/usr/bin/python3 -S" in detached_block
    for forbidden in (
        "cryptography.hazmat",
        "Ed25519PrivateKey",
        "pip install",
        "git ",
        "curl ",
        "wget ",
        "docker ",
        "$GITHUB_WORKSPACE",
        "/github/workspace",
    ):
        assert forbidden not in detached_block, forbidden
    checks += 1
    print("[GREEN] cryptography-backed differential baseline precedes exact detached stdlib verification")

    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    lower_workflow = workflow.lower()
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
        assert forbidden not in lower_workflow, forbidden
    lower_doc = doc.lower()
    assert "not** used by axven consensus" in lower_doc
    assert "production consensus remains python-authoritative" in lower_doc
    assert "rollback-resistant external trust storage" in lower_doc
    checks += 1
    print("[GREEN] RUST-030 grants no publication, signing, deployment or production-routing privilege")

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
    print("RUST-030 stdlib monotonic trust policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
