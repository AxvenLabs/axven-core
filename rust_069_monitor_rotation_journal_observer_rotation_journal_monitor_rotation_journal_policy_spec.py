#!/usr/bin/env python3
"""RUST-069 static policy for TEST-ONLY checkpoint-monitor rotation journal continuity."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_069.md"
VERIFY = ROOT / "rust_069_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_verify.py"
FIXTURE = ROOT / "rust_069_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_fixture.py"
SELFTEST = ROOT / "rust_069_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal.yml"
BASE = ROOT / "rust_068_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_verify.py"
EXPECTED_RUST068_GIT_BLOB = "02d78a385b27e09f50535380286470992f99b533"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_066_monitor_rotation_journal_observer_rotation_journal_monitor_verify",
    "rust_067_monitor_rotation_journal_observer_rotation_journal_monitor_set_rotation_verify",
    "rust_068_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_066_monitor_rotation_journal_observer_rotation_journal_monitor_verify",
    "rust_069_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST068_GIT_BLOB
    require(
        verify,
        ("import rust_068_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_verify as rotation2_verify",),
        "RUST-069 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-068 verifier is composed")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-069 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "frozenset(target) != monitor_verify.TARGET_KEYS",
            '"rotation_auth_sha256"', '"monitor_bundle_sha256"',
            '"cumulative_revoked_monitor_ids"', '"predecessor_entry_sha256"',
            '"previous_checkpoint_sha256"', '"observed_target_sha256"',
            "final RUST-069 monitor rotation journal rewrites checkpointed prefix",
            "observed same-parent monitor-rotation-journal observer-rotation-journal monitor-rotation-journal checkpoint fork",
        ),
        "RUST-069 verifier",
    )
    checks += 1
    print("[GREEN] append-only history, full-target digest, checkpoint chaining and split-view rejection are fixed")

    require(
        fixture,
        (
            '"89" * 32', '"99" * 32', '"a9" * 32', '"b9" * 32',
            "Ed25519PrivateKey", "RUST-069 TEST-only journal monitor public-key pin mismatch",
        ),
        "RUST-069 producer fixture",
    )
    require(
        selftest,
        (
            "RUST-069 prefix checkpoint availability: 3/3 valid two-monitor subsets accepted",
            "RUST-069 final checkpoint availability: 3/3 valid two-monitor subsets accepted",
            "35/35 expected cases passed",
            "observed-valid-same-parent-monitor-rotation-journal-fork",
        ),
        "RUST-069 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and 35-case availability/fork matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust069",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            'test ! -e "$c/rust_069_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_fixture.py"',
            'test "$(wc -l < /tmp/axven-rust069-paths)" -eq 100',
        ),
        "RUST-069 workflow",
    )
    for forbidden in (
        "contents: write", "id-token: write", "packages: write", "pull-requests: write",
        "actions/upload-artifact", "attest", "release", "deploy",
    ):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, manifest-bounded and non-publishing")

    require(
        doc,
        (
            "M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5",
            "three monotonic hash-chained entries", "prefix checkpoint covers entries 0..1",
            "final checkpoint covers entries 0..2", "2-of-3 signatures",
            "complete inherited RUST-066 canonical checkpoint target",
            "same-parent final monitor-rotation-journal observer-rotation-journal monitor-rotation-journal checkpoint fork",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-069 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only append-only journal boundary")

    assert checks == 6
    print("RUST-069 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
