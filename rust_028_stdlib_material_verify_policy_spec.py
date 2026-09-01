#!/usr/bin/env python3
"""RUST-028: static policy for the stdlib-only detached Ed25519 material verifier."""
from __future__ import annotations

import ast
from pathlib import Path
import axven

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-stdlib-material-consumer.yml"
VERIFIER = ROOT / "rust_028_stdlib_material_verify.py"
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
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                roots.add(node.module.split(".", 1)[0])
    return roots


def main() -> None:
    checks = 0
    workflow = text(WORKFLOW)
    verifier = text(VERIFIER)
    doc = text("RUST_028.md")

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
    print("[GREEN] RUST-028 detached verifier imports only Python stdlib and has no signing capability")

    for marker in (
        "FIELD_Q = 2**255 - 19",
        "GROUP_L = 2**252 + 27742317777372353535851937790883648493",
        "hashlib.sha512",
        "s >= GROUP_L",
        "_points_equal(_scalar_mult(BASE_POINT, s), _add(r, _scalar_mult(a, k)))",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "RUST-028 RFC 8032 Ed25519 vector: GREEN",
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] Ed25519 verifier is pinned to RFC 8032 arithmetic and known-answer validation")

    for marker in (
        "bash rust_025_upstream_authenticated_detached_build.sh",
        "python rust_026_build_material_attestation.py generate",
        "python rust_026_build_material_attestation.py seal",
        "Bridge RUST-023 manifest canonical encoding",
        "Differential verification against RUST-027 consumer",
        "Detached RUST-028 stdlib-only consumer",
        "/usr/bin/python3 -S",
        "env -i",
        "PYTHONNOUSERSITE=1",
        'test "$(find "$consumer" -maxdepth 1 -type f | wc -l)" -eq 3',
        'python "$consumer/verifier.py" verify',
        'python "$consumer/verifier.py" selftest',
    ):
        # The detached commands intentionally use /usr/bin/python3 -S rather than the plain-python marker.
        if marker.startswith('python "$consumer'):
            assert marker.replace("python ", "/usr/bin/python3 -S ") in workflow, marker
        else:
            assert marker in workflow, marker
    assert "10/10 expected cases passed" in verifier
    checks += 1
    print("[GREEN] RUST-028 consumer runs with -S/env-i and retains the 10/10 fail-closed evidence contract")

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
    assert "stdlib-only" in doc.lower()
    assert "does not upload or publish" in doc.lower()
    checks += 1
    print("[GREEN] RUST-028 adds no publication, OIDC, production signing or deployment privilege")

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
    print("RUST-028 stdlib-only material consumer policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
