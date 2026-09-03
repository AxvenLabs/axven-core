#!/usr/bin/env python3
"""RUST-098 static policy for TEST-ONLY RUST-097 checkpoint monitoring."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_098.md"
VERIFY = ROOT / "rust_098_rust097_checkpoint_monitor_verify.py"
FIXTURE = ROOT / "rust_098_rust097_checkpoint_monitor_fixture.py"
SELFTEST = ROOT / "rust_098_rust097_checkpoint_monitor_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-rust098-rust097-checkpoint-monitor.yml"
BASE = ROOT / "rust_097_rust094_checkpoint_monitor_rotation_journal_verify.py"
PREDECESSOR_WORKFLOW = ROOT / ".github/workflows/native-rust097-checkpoint-monitor-rotation-journal.yml"
EXPECTED_RUST097_GIT_BLOB = "515bb1e7a3d2cbb636a1dde325a357d666c20512"
EXPECTED_RUST097_WORKFLOW_GIT_BLOB = "dff9808c0ee56d9cfce3f506548f5527f2c59dda"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_097_rust094_checkpoint_monitor_rotation_journal_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_097_rust094_checkpoint_monitor_rotation_journal_verify",
    "rust_098_rust097_checkpoint_monitor_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST097_GIT_BLOB
    assert blob(PREDECESSOR_WORKFLOW.read_bytes()) == EXPECTED_RUST097_WORKFLOW_GIT_BLOB
    require(
        verify,
        ("import rust_097_rust094_checkpoint_monitor_rotation_journal_verify as journal_verify",),
        "RUST-098 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-097 verifier and workflow are pinned")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-098 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "CHECKPOINT_SHA_KEY", "CHECKPOINT_STATEMENT_SHA_KEY",
            "production RUST-098 monitoring forbidden",
            "observed monitor same-parent RUST-097 monitor rotation journal checkpoint fork",
            "monitor_set_sequence", "monitor_set_sha256", "entry_count",
            "journal_sha256", "head_entry_sha256", "previous_checkpoint_sha256",
            "monitored_checkpoint_sha256", "monitored_checkpoint_statement_sha256",
            "observed_target_sha256", "activation_source_commit",
            "base_paths[175]", "base_paths[176]", "path_args[177]",
        ),
        "RUST-098 verifier",
    )
    checks += 1
    print("[GREEN] exact 12-field RUST-097 checkpoint binding, quorum, and same-parent rejection are fixed")

    require(
        fixture,
        (
            '"9b" * 32', '"ab" * 32', '"bb" * 32', "Ed25519PrivateKey",
            "RUST-098 TEST-only monitor public-key pin mismatch",
        ),
        "RUST-098 producer fixture",
    )
    require(
        selftest,
        (
            "3/3 valid two-monitor subsets accepted",
            "signed observed same-parent fork evidence validated",
            "27/27 expected cases passed",
            "rust097-checkpoint-replay",
        ),
        "RUST-098 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and availability/replay/fork matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust098",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            'test ! -e "$c/rust_098_rust097_checkpoint_monitor_fixture.py"',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 71',
            "expected 177 RUST-097 paths", "expected 178 RUST-098 paths",
            "axven-rust098-monitor-bundle.json",
        ),
        "RUST-098 workflow",
    )
    for forbidden in (
        "contents: write", "id-token: write", "packages: write", "pull-requests: write",
        "actions/upload-artifact", "attest", "release", "deploy",
    ):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, manifest-bounded, and non-publishing")

    require(
        doc,
        (
            "TEST-ONLY", "2-of-3", "3/3",
            "exact RUST-097 final checkpoint SHA-256",
            "same-parent", "RUST-097 checkpoint replay",
            "71-file", "178-path",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-098 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only monitoring boundary")

    assert checks == 6
    print("RUST-098 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
