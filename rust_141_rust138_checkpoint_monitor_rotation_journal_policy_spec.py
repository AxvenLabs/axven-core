#!/usr/bin/env python3
"""RUST-141 static policy for TEST-ONLY append-only RUST-138 monitor rotation journal."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_141.md"
VERIFY = ROOT / "rust_141_rust138_checkpoint_monitor_rotation_journal_verify.py"
FIXTURE = ROOT / "rust_141_rust138_checkpoint_monitor_rotation_journal_fixture.py"
SELFTEST = ROOT / "rust_141_rust138_checkpoint_monitor_rotation_journal_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-rust141-checkpoint-monitor-rotation-journal.yml"
BASE = ROOT / "rust_140_multistep_rust138_checkpoint_monitor_rotation_verify.py"
PREDECESSOR_WORKFLOW = ROOT / ".github/workflows/native-rust140-multistep-rust138-checkpoint-monitor-rotation.yml"
EXPECTED_RUST140_GIT_BLOB = "71191f914275257a51c17540e3c6af09ba594164"
EXPECTED_RUST140_WORKFLOW_GIT_BLOB = "5c2534b9d31087e7a3ced97911d596c48ebd86a0"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_138_rust137_checkpoint_monitor_verify",
    "rust_139_rust138_checkpoint_monitor_rotation_verify",
    "rust_140_multistep_rust138_checkpoint_monitor_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_138_rust137_checkpoint_monitor_verify",
    "rust_141_rust138_checkpoint_monitor_rotation_journal_verify",
}


def text(path: Path) -> str:
    value = path.read_text(encoding="utf-8")
    if "\r" in value:
        raise AssertionError(f"CR forbidden: {path.name}")
    return value


def blob(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()


def imported_roots(source: str) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def require(haystack: str, needles: tuple[str, ...], label: str) -> None:
    missing = [needle for needle in needles if needle not in haystack]
    if missing:
        raise AssertionError(f"{label} missing required markers: {missing}")


def main() -> None:
    doc = text(DOC); verify = text(VERIFY); fixture = text(FIXTURE)
    selftest = text(SELFTEST); workflow = text(WORKFLOW); checks = 0

    assert blob(BASE.read_bytes()) == EXPECTED_RUST140_GIT_BLOB
    assert blob(PREDECESSOR_WORKFLOW.read_bytes()) == EXPECTED_RUST140_WORKFLOW_GIT_BLOB
    require(
        verify,
        (
            "import rust_138_rust137_checkpoint_monitor_verify as monitor_verify",
            "import rust_140_multistep_rust138_checkpoint_monitor_rotation_verify as rotation2_verify",
        ),
        "RUST-141 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-140 verifier and workflow are pinned")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
        "AXVEN_NATIVE_RUST137_", "rust_134_rust141_checkpoint_monitor_verify",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-141 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "AXVEN_NATIVE_RUST141_MONITOR_ROTATION_JOURNAL_CHECKPOINT_V1", "target_digest", "predecessor_entry_sha256",
            "cumulative_revoked_monitor_ids",
            "final RUST-141 monitor rotation journal rewrites checkpointed prefix",
            "observed same-parent RUST-141 monitor rotation journal checkpoint fork",
            "rotation1_verify.NEW_PINNED_MONITORS", "rotation2_verify.FINAL_PINNED_MONITORS",
            "base_paths[286]", "base_paths[287]", "base_paths[293]", "path_args[294:298]",
        ),
        "RUST-141 verifier",
    )
    checks += 1
    print("[GREEN] append-only hash chain, exact target/evidence binding, quorum, and fork rejection are fixed")

    require(
        fixture,
        (
            '"ce" * 32', '"de" * 32', '"ee" * 32', '"fe" * 32',
            "Ed25519PrivateKey", "RUST-141 TEST-only journal monitor public-key pin mismatch",
        ),
        "RUST-141 producer fixture",
    )
    require(
        selftest,
        (
            "prefix checkpoint availability: 3/3 valid two-monitor subsets accepted",
            "final checkpoint availability: 3/3 valid two-monitor subsets accepted",
            "35/35 expected cases passed",
            "observed-valid-same-parent-monitor-rotation-journal-fork",
        ),
        "RUST-141 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and 3/3 + 3/3 + 35/35 availability/fork matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust141",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            '"rust_*.py"', '"RUST_*.md"', 'printf -v n3 "%03d" "$n"',
            'test ! -e "$c/rust_141_rust138_checkpoint_monitor_rotation_journal_fixture.py"',
            'test "$(wc -l < /tmp/axven-rust141-paths)" -eq 298',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 114',
            "expected 294 RUST-140 paths", "expected 298 RUST-141 paths",
        ),
        "RUST-141 workflow",
    )
    for forbidden in (
        "contents: write", "id-token: write", "packages: write", "pull-requests: write",
        "actions/upload-artifact", "attest", "release", "deploy",
    ):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, 100-boundary-safe, read-only, and non-publishing")

    require(
        doc,
        (
            "M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5",
            "cumulative revocation `[M1, M2]`",
            "2-of-3", "3/3 valid two-monitor subsets", "35/35 expected cases",
            "same-parent final checkpoint", "298-path", "114-file",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-141 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only journal boundary")

    assert checks == 6
    print("RUST-141 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
