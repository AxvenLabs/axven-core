#!/usr/bin/env python3
"""RUST-019: static policy for offline native dependency archive closure."""
from __future__ import annotations

from pathlib import Path

import axven
import rust_019_offline_dependency_closure as closure

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-offline-dependency-closure.yml"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")
FORBIDDEN_VERIFIER = (
    "import subprocess",
    "from subprocess",
    "import socket",
    "from socket",
    "urllib",
    "requests",
    "http.client",
    "os.environ",
    "GITHUB_",
    "import axven",
    "from axven",
    "docker",
)


def text(path: Path | str) -> str:
    target = path if isinstance(path, Path) else ROOT / path
    return target.read_text(encoding="utf-8")


def main() -> None:
    checks = 0
    verifier = text("rust_019_offline_dependency_closure.py")
    workflow = text(WORKFLOW)
    doc = text("RUST_019.md")

    assert closure.CRATES_IO_SOURCE == "registry+https://github.com/rust-lang/crates.io-index"
    assert closure.EXPECTED_REQUIREMENT == "maturin==1.15.0"
    assert 'tomllib.loads(raw.decode("utf-8"))' in verifier
    assert 'filename = f"{name}-{version}.crate"' in verifier
    assert 'if _sha256_file(path) != digest:' in verifier
    assert 'if _sha256_file(wheel) not in allowed_hashes:' in verifier
    assert "RUST-019 offline dependency closure fail-closed contract: 8/8 GREEN" in verifier
    checks += 1
    print("[GREEN] RUST-019 derives crate and Maturin archive authority from existing lock files")

    for marker in FORBIDDEN_VERIFIER:
        assert marker not in verifier, marker
    for marker in (
        "tarfile.open(path, mode=\"r:gz\")",
        "member.issym()",
        "member.islnk()",
        "member.ischr()",
        "member.isblk()",
        "member.isfifo()",
        "archive.testzip()",
        "_wheel_is_symlink(info)",
        "actual_names != set(expected)",
    ):
        assert marker in verifier, marker
    checks += 1
    print("[GREEN] detached verifier has no process/network/GitHub trust and rejects unsafe archive structure")

    for marker in (
        '"RUST_019.md"',
        '"rust_019_offline_dependency_closure.py"',
        '"rust_019_offline_dependency_policy_spec.py"',
    ):
        assert workflow.count(marker) == 2, marker
    for marker in (
        "python rust_019_offline_dependency_policy_spec.py",
        "cargo fetch --locked --manifest-path native/axven_native/Cargo.toml",
        "python rust_019_offline_dependency_closure.py collect-crates",
        "python -m pip download",
        "--no-deps",
        "--only-binary=:all:",
        "--require-hashes",
        "Verify detached RUST-019 dependency closure",
        "RUST-019 dependency closure mutation contract",
        "Reverify detached RUST-019 dependency closure",
        "env -i",
        "PYTHONDONTWRITEBYTECODE=1",
    ):
        assert marker in workflow, marker
    verify_at = workflow.index("Verify detached RUST-019 dependency closure")
    selftest_at = workflow.index("RUST-019 dependency closure mutation contract")
    reverify_at = workflow.index("Reverify detached RUST-019 dependency closure")
    assert verify_at < selftest_at < reverify_at
    checks += 1
    print("[GREEN] producer collection is separated from env-clean verify -> mutate -> reverify consumer checks")

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
    assert "does **not** upload or publish artifacts" in doc.lower()
    assert "does **not** yet route rust-018 through that closure" in doc.lower()
    checks += 1
    print("[GREEN] dependency-closure checkpoint adds no publication, OIDC, signing, deployment, or build-routing privilege")

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
    print("RUST-019 offline dependency closure policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
