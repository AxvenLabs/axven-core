#!/usr/bin/env python3
"""RUST-017: static policy for detached Git commit/tree proof."""
from __future__ import annotations

from pathlib import Path

import axven
import rust_014_reproducible_attestation as producer
import rust_016_offline_build_input_verify as sourcecheck
import rust_017_offline_git_tree_verify as consumer

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
    source = text("rust_017_offline_git_tree_verify.py")
    doc = text("RUST_017.md")

    assert consumer.BUILD_INPUT_KEYS == sourcecheck.BUILD_INPUT_KEYS
    assert consumer.BUILD_INPUT_KEYS == frozenset(producer.BUILD_INPUTS)
    assert consumer.EXPECTED_TREE_COUNT == 6
    checks += 1
    print("[GREEN] RUST-017 pins the exact RUST-014/RUST-016 signed input set and six-tree closure")

    for marker in FORBIDDEN_CONSUMER_PATTERNS:
        assert marker not in source, marker
    for required in (
        "import rust_015_offline_repro_consumer_verify as evidence",
        "import rust_016_offline_build_input_verify as sourcecheck",
        "hashlib.sha1(",
        "usedforsecurity=False",
        "def _parse_commit(",
        "def _parse_tree(",
        "visited_tree_oids",
        'committer_epoch != provenance["source_date_epoch"]',
        'actual_commit != source_commit',
        'actual_blob != child_oid',
        "RUST-017 detached Git commit/tree fail-closed contract: 10/10 GREEN",
    ):
        assert required in source, required
    checks += 1
    print("[GREEN] detached consumer directly validates commit/tree/blob linkage with no Git command or network dependency")

    for marker in (
        '"RUST_017.md"',
        '"rust_017_offline_git_tree_verify.py"',
        '"rust_017_offline_git_tree_policy_spec.py"',
    ):
        assert workflow.count(marker) == 2, marker
    for marker in (
        "python rust_017_offline_git_tree_policy_spec.py",
        "Prepare detached RUST-017 Git object bundle",
        'git cat-file commit "$AXVEN_SOURCE_SHA"',
        'git cat-file tree "$oid"',
        "git hash-object -t commit --stdin",
        "git hash-object -t tree --stdin",
        'find "$consumer" -type d -name \'__pycache__\' -prune -exec rm -rf {} +',
        'test "$(find "$consumer" -type f \\( -name \'*.pyc\' -o -name \'*.pyo\' \\) | wc -l)" -eq 0',
        'test ! -e "$consumer/.git"',
        'test "$(find "$consumer" -type f | wc -l)" -eq 25',
        'test "$(find "$consumer/git-objects" -type f | wc -l)" -eq 7',
        'test "$(find "$consumer/git-objects/trees" -type f -name \'*.tree\' | wc -l)" -eq 6',
        "env -i",
        "python rust_017_offline_git_tree_verify.py verify",
        "python rust_017_offline_git_tree_verify.py selftest",
    ):
        assert marker in workflow, marker
    assert workflow.index("Reverify detached RUST-016 signed build inputs") < workflow.index(
        "Prepare detached RUST-017 Git object bundle"
    )
    checks += 1
    print("[GREEN] workflow exports a cache-free minimum raw Git object closure and verifies it only after RUST-016")

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
    assert "does **not** rely on sha-1 alone" in doc.lower()
    assert "does not publish artifacts" in doc.lower()
    checks += 1
    print("[GREEN] Git SHA-1 is scoped to graph identity and no publication/OIDC/signing privilege is added")

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
    print("RUST-017 detached Git tree policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
