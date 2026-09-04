#!/usr/bin/env python3
"""RUST-134 static policy for TEST-ONLY RUST-133 checkpoint monitoring."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_134.md"
VERIFY = ROOT / "rust_134_rust133_checkpoint_monitor_verify.py"
FIXTURE = ROOT / "rust_134_rust133_checkpoint_monitor_fixture.py"
SELFTEST = ROOT / "rust_134_rust133_checkpoint_monitor_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-rust134-rust133-checkpoint-monitor.yml"
BASE = ROOT / "rust_133_rust130_checkpoint_monitor_rotation_journal_verify.py"
PREDECESSOR_WORKFLOW = ROOT / ".github/workflows/native-rust133-checkpoint-monitor-rotation-journal.yml"
EXPECTED_RUST133_GIT_BLOB = "4fd8786fa0042d5110a967d1d44a34ab8279b65c"
EXPECTED_RUST133_WORKFLOW_GIT_BLOB = "ceeaecf879e626ef11c9d355902737f729b13264"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_133_rust130_checkpoint_monitor_rotation_journal_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_133_rust130_checkpoint_monitor_rotation_journal_verify",
    "rust_134_rust133_checkpoint_monitor_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST133_GIT_BLOB
    assert blob(PREDECESSOR_WORKFLOW.read_bytes()) == EXPECTED_RUST133_WORKFLOW_GIT_BLOB
    require(
        verify,
        ("import rust_133_rust130_checkpoint_monitor_rotation_journal_verify as journal_verify",),
        "RUST-134 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-133 verifier and workflow are pinned")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-134 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "CHECKPOINT_SHA_KEY", "CHECKPOINT_STATEMENT_SHA_KEY",
            "production RUST-134 monitoring forbidden",
            "observed monitor same-parent RUST-133 monitor rotation journal checkpoint fork",
            "monitor_set_sequence", "monitor_set_sha256", "entry_count",
            "journal_sha256", "head_entry_sha256", "previous_checkpoint_sha256",
            "monitored_checkpoint_sha256", "monitored_checkpoint_statement_sha256",
            "observed_target_sha256", "activation_source_commit",
            "base_paths[274]", "base_paths[275]", "path_args[276]",
        ),
        "RUST-134 verifier",
    )
    checks += 1
    print("[GREEN] exact 12-field RUST-133 checkpoint binding, quorum, and same-parent rejection are fixed")

    require(
        fixture,
        (
            '"6e" * 32', '"7e" * 32', '"8e" * 32', "Ed25519PrivateKey",
            "RUST-134 TEST-only monitor public-key pin mismatch",
        ),
        "RUST-134 producer fixture",
    )
    require(
        selftest,
        (
            "3/3 valid two-monitor subsets accepted",
            "signed observed same-parent fork evidence validated",
            "27/27 expected cases passed",
            "rust133-checkpoint-replay",
        ),
        "RUST-134 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and availability/replay/fork matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust134",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            '"rust_*.py"', '"RUST_*.md"', 'printf -v n3 "%03d" "$n"',
            'test ! -e "$c/rust_134_rust133_checkpoint_monitor_fixture.py"',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 107',
            "expected 276 RUST-133 paths", "expected 277 RUST-134 paths",
            "axven-rust134-monitor-bundle.json",
        ),
        "RUST-134 workflow",
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
            "TEST-ONLY", "2-of-3", "3/3",
            "exact RUST-133 final checkpoint SHA-256",
            "same-parent", "RUST-133 checkpoint replay",
            "107-file", "277-path",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-134 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only monitoring boundary")

    assert checks == 6
    print("RUST-134 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
