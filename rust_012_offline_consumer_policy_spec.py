#!/usr/bin/env python3
"""RUST-012: static policy contract for the detached offline consumer verifier."""
from __future__ import annotations

import ast
from pathlib import Path

import axven

ROOT = Path(__file__).resolve().parent
VERIFIER = ROOT / "rust_012_offline_consumer_verify.py"
WORKFLOW = ROOT / ".github/workflows/native-portable-attestation.yml"
DOC = ROOT / "RUST_012.md"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")


def text(path: Path | str) -> str:
    target = path if isinstance(path, Path) else ROOT / path
    return target.read_text(encoding="utf-8")


def main() -> None:
    checks = 0
    source = text(VERIFIER)
    workflow = text(WORKFLOW)
    doc = text(DOC)
    tree = ast.parse(source, filename=str(VERIFIER))

    imported: set[str] = set()
    string_literals: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            string_literals.add(node.value)
    forbidden_imports = {
        "axven",
        "core",
        "p2p",
        "rpc",
        "wallet",
        "axven_core",
        "rust_011_portable_attestation",
        "os",
        "subprocess",
        "socket",
        "urllib",
        "http",
        "requests",
    }
    assert not (imported & forbidden_imports), sorted(imported & forbidden_imports)
    for marker in ("GITHUB_", "git ", "git\"", "docker", "urlopen", "requests."):
        assert marker not in source, marker
    assert ".git" not in string_literals
    checks += 1
    print("[GREEN] detached verifier has no repo, GitHub-env, git, Docker, or network dependency")

    required_pins = (
        'PROVENANCE_SCHEMA = "axven-native-portable-provenance-v1"',
        'ATTESTATION_SCHEMA = "axven-native-portable-attestation-envelope-v1"',
        'PAYLOAD_TYPE = "application/vnd.axven.native-portable-provenance.v1+json"',
        'KEY_ID = "rust-011-test-only-ed25519-v1"',
        'REPOSITORY = "AxvenLabs/axven-core"',
        'WHEEL_FILENAME = "axven_native-0.1.0-cp313-abi3-manylinux_2_28_x86_64.whl"',
        '"python": "3.13.13"',
        '"rust": "1.98.0"',
        '"maturin": "1.15.0"',
        '"pyo3": "0.29.2"',
        '"production_consensus"] != "python"',
    )
    for marker in required_pins:
        assert marker in source, marker
    assert "public_key" not in source.split("ENVELOPE_KEYS =", 1)[1].split(")", 1)[0]
    assert "Ed25519PublicKey.from_public_bytes(PINNED_PUBLIC_KEY).verify" in source
    checks += 1
    print("[GREEN] artifact, source, builder, consensus, and TEST-ONLY trust-root policy are independently pinned")

    for marker in (
        "wheel byte mutation",
        "renamed wheel/path confusion",
        "artifact digest mutation",
        "builder-image substitution",
        "source-repository substitution",
        "unexpected provenance field",
        "non-canonical provenance",
        "signature mutation",
        "key-id substitution",
        "embedded trust-root substitution",
        "non-canonical envelope",
        "11/11 GREEN",
    ):
        assert marker in source, marker
    assert "path.is_symlink()" in source
    assert "len(resolved) != 3" in source
    checks += 1
    print("[GREEN] detached artifact/evidence mutation and path-confusion cases fail closed")

    assert '"RUST_012.md"' in workflow
    assert '"rust_012_offline_consumer_verify.py"' in workflow
    assert '"rust_012_offline_consumer_policy_spec.py"' in workflow
    assert "python rust_012_offline_consumer_policy_spec.py" in workflow
    assert "env -i" in workflow
    assert "PYTHONNOUSERSITE=1" in workflow
    assert "PYTHONDONTWRITEBYTECODE=1" in workflow
    assert 'test "$(find "$consumer" -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 4' in workflow
    assert 'test ! -e "$consumer/.git"' in workflow
    assert "rust_012_offline_consumer_verify.py verify" in workflow
    assert "rust_012_offline_consumer_verify.py selftest" in workflow
    assert "permissions:\n  contents: read" in workflow
    for marker in (
        "id-token: write",
        "attestations: write",
        "packages: write",
        "contents: write",
        "actions/upload-artifact",
        "maturin publish",
        "twine upload",
        "docker push",
    ):
        assert marker not in workflow.lower(), marker
    checks += 1
    print("[GREEN] CI executes exactly the detached four-file bundle under an empty environment without publication privilege")

    assert "not production release authentication" in doc.lower()
    assert "production rust routing" in doc.lower()
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
    print("RUST-012 detached offline consumer policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
