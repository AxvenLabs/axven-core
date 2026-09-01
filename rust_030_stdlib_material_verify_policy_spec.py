#!/usr/bin/env python3
"""RUST-030: static policy for byte-identical stdlib-only material verification."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import axven

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-stdlib-material-consumer.yml"
VERIFIER = ROOT / "rust_030_stdlib_material_verify.py"
DOC = ROOT / "RUST_030.md"
EXPECTED_GIT_BLOB = "0688cac21315533a3ff0fd760d28a44a9c897a6f"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")
ALLOWED_IMPORTS = {"base64", "binascii", "hashlib", "json", "os", "pathlib", "shutil", "stat", "sys", "tempfile", "__future__"}
PUBLIC_KEY = "4dd000548d1ed66588e6c23531163bd12c9c5dbca5eb932d4c6a75cde6525064"


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
    header = f"blob {len(raw)}\0".encode("ascii")
    return hashlib.sha1(header + raw).hexdigest()


def main() -> None:
    checks = 0
    workflow = text(WORKFLOW)
    verifier_raw = VERIFIER.read_bytes()
    verifier = verifier_raw.decode("utf-8")
    doc = text(DOC)

    assert git_blob_sha(verifier_raw) == EXPECTED_GIT_BLOB
    assert "byte-for-byte" in doc.lower()
    assert EXPECTED_GIT_BLOB in doc
    assert "historical `rust-028` diagnostic strings" in doc.lower()
    checks += 1
    print("[GREEN] RUST-030 verifier is byte-identical to the reviewed superseded-PR implementation")

    roots = imported_roots(verifier)
    assert roots <= ALLOWED_IMPORTS, roots - ALLOWED_IMPORTS
    for forbidden in (
        "cryptography",
        "nacl",
        "OpenSSL",
        "Ed25519PrivateKey",
        "TEST_SEED",
        "def seal",
        "subprocess",
        "import axven",
        "from axven",
        "import rust_0",
        "from rust_0",
    ):
        assert forbidden not in verifier, forbidden
    assert PUBLIC_KEY in verifier
    checks += 1
    print("[GREEN] detached verifier imports only Python stdlib and has no signing capability")

    for marker in (
        "FIELD_Q = 2**255 - 19",
        "GROUP_L = 2**252 + 27742317777372353535851937790883648493",
        "hashlib.sha512",
        "s >= GROUP_L",
        "_points_equal(_scalar_mult(BASE_POINT, s), _add(r, _scalar_mult(a, k)))",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "10/10 expected cases passed",
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] RFC 8032 arithmetic, known-answer test and 10/10 fail-closed contract are retained")

    for marker in (
        "python rust_030_stdlib_material_verify_policy_spec.py",
        "bash rust_025_upstream_authenticated_detached_build.sh",
        "python rust_026_build_material_attestation.py generate",
        "python rust_026_build_material_attestation.py seal",
        "Differential verification against RUST-027 consumer",
        "Detached RUST-030 stdlib-only consumer",
        "rust_030_stdlib_material_verify.py",
        "/usr/bin/python3 -S",
        "env -i",
        "PYTHONNOUSERSITE=1",
        'test "$(find "$consumer" -maxdepth 1 -type f | wc -l)" -eq 3',
    ):
        assert marker in workflow, marker
    assert "rust_028_stdlib_material_verify" not in workflow
    checks += 1
    print("[GREEN] RUST-030 replays RUST-025/026/027 evidence and detaches a three-file -S/env-i consumer")

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
    assert "does not upload or publish" in doc.lower()
    checks += 1
    print("[GREEN] RUST-030 adds no publication, OIDC, production signing or deployment privilege")

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
    print("RUST-030 stdlib-only material consumer policy contract: 6/6 GREEN")


if __name__ == "__main__":
    main()
