#!/usr/bin/env python3
"""RUST-137 static policy for TEST-ONLY append-only RUST-134 monitor rotation journal."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_137.md"
VERIFY = ROOT / "rust_137_rust134_checkpoint_monitor_rotation_journal_verify.py"
FIXTURE = ROOT / "rust_137_rust134_checkpoint_monitor_rotation_journal_fixture.py"
SELFTEST = ROOT / "rust_137_rust134_checkpoint_monitor_rotation_journal_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-rust137-checkpoint-monitor-rotation-journal.yml"
BASE = ROOT / "rust_136_multistep_rust134_checkpoint_monitor_rotation_verify.py"
PREDECESSOR_WORKFLOW = ROOT / ".github/workflows/native-rust136-multistep-checkpoint-monitor-rotation.yml"
EXPECTED_RUST136_GIT_BLOB = "8d72eb2b1e3449afda974b47e7d9e7531f5f1c11"
EXPECTED_RUST136_WORKFLOW_GIT_BLOB = "f22028ea3a0ff6ebd370cfe099c4dab8402b8b7a"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_134_rust133_checkpoint_monitor_verify",
    "rust_135_rust134_checkpoint_monitor_rotation_verify",
    "rust_136_multistep_rust134_checkpoint_monitor_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_134_rust133_checkpoint_monitor_verify",
    "rust_137_rust134_checkpoint_monitor_rotation_journal_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST136_GIT_BLOB
    assert blob(PREDECESSOR_WORKFLOW.read_bytes()) == EXPECTED_RUST136_WORKFLOW_GIT_BLOB
    require(
        verify,
        (
            "import rust_134_rust133_checkpoint_monitor_verify as monitor_verify",
            "import rust_136_multistep_rust134_checkpoint_monitor_rotation_verify as rotation2_verify",
        ),
        "RUST-137 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-136 verifier and workflow are pinned")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
        "AXVEN_NATIVE_RUST133_", "rust_134_rust137_checkpoint_monitor_verify",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-137 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "AXVEN_NATIVE_RUST137_MONITOR_ROTATION_JOURNAL_CHECKPOINT_V1", "target_digest", "predecessor_entry_sha256",
            "cumulative_revoked_monitor_ids",
            "final RUST-137 monitor rotation journal rewrites checkpointed prefix",
            "observed same-parent RUST-137 monitor rotation journal checkpoint fork",
            "rotation1_verify.NEW_PINNED_MONITORS", "rotation2_verify.FINAL_PINNED_MONITORS",
            "base_paths[275]", "base_paths[276]", "base_paths[282]", "path_args[283:287]",
        ),
        "RUST-137 verifier",
    )
    checks += 1
    print("[GREEN] append-only hash chain, exact target/evidence binding, quorum, and fork rejection are fixed")

    require(
        fixture,
        (
            '"7e" * 32', '"8e" * 32', '"9e" * 32', '"ae" * 32',
            "Ed25519PrivateKey", "RUST-137 TEST-only journal monitor public-key pin mismatch",
        ),
        "RUST-137 producer fixture",
    )
    require(
        selftest,
        (
            "prefix checkpoint availability: 3/3 valid two-monitor subsets accepted",
            "final checkpoint availability: 3/3 valid two-monitor subsets accepted",
            "35/35 expected cases passed",
            "observed-valid-same-parent-monitor-rotation-journal-fork",
        ),
        "RUST-137 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and 3/3 + 3/3 + 35/35 availability/fork matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust137",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            '"rust_*.py"', '"RUST_*.md"', 'printf -v n3 "%03d" "$n"',
            'test ! -e "$c/rust_137_rust134_checkpoint_monitor_rotation_journal_fixture.py"',
            'test "$(wc -l < /tmp/axven-rust137-paths)" -eq 287',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 110',
            "expected 283 RUST-136 paths", "expected 287 RUST-137 paths",
        ),
        "RUST-137 workflow",
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
            "same-parent final checkpoint", "287-path", "110-file",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-137 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only journal boundary")

    assert checks == 6
    print("RUST-137 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
