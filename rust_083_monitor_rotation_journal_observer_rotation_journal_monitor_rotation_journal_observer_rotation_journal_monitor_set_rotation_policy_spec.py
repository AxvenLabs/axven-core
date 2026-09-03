#!/usr/bin/env python3
"""RUST-083 static policy for TEST-ONLY monitor-set rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_083.md"
VERIFY = ROOT / "rust_083_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_set_rotation_verify.py"
FIXTURE = ROOT / "rust_083_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_set_rotation_fixture.py"
SELFTEST = ROOT / "rust_083_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_set_rotation_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-observer-rotation-journal-monitor-set-rotation.yml"
BASE = ROOT / "rust_082_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_verify.py"
PREDECESSOR_WORKFLOW = ROOT / ".github/workflows/native-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-observer-rotation-journal-monitor.yml"
EXPECTED_RUST082_GIT_BLOB = "690891eda37cc36439ec1e6a4b4c5b91a35bdc45"
EXPECTED_RUST082_WORKFLOW_GIT_BLOB = "c03e08a9125c7f746ce233a324735f43d5afae15"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_082_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_082_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_verify",
    "rust_083_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_set_rotation_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST082_GIT_BLOB
    assert blob(PREDECESSOR_WORKFLOW.read_bytes()) == EXPECTED_RUST082_WORKFLOW_GIT_BLOB
    require(
        verify,
        ("import rust_082_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_verify as monitor_verify",),
        "RUST-083 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-082 verifier and workflow are pinned")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-083 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "OLD_SET_SEQUENCE = 0", "NEW_SET_SEQUENCE = 1",
            "predecessor_monitor_bundle_sha256", "revoked_monitor_ids",
            "RUST-083 predecessor monitor bundle mismatch",
            "observed RUST-083 successor same-parent checkpoint fork",
            "*monitor_verify.TARGET_KEYS",
            "production monitor rotation forbidden in RUST-083",
        ),
        "RUST-083 verifier",
    )
    checks += 1
    print("[GREEN] rotation continuity, full target binding, revocation, and fork rejection are fixed")

    require(
        fixture,
        ('"59" * 32', '"69" * 32', '"79" * 32', '"89" * 32', "Ed25519PrivateKey"),
        "RUST-083 producer fixture",
    )
    require(
        selftest,
        (
            "3/3 valid two-monitor subsets accepted",
            "48/48 expected cases passed",
            "revoked-monitor-resurrection", "old-rust082-bundle-replay",
            "observed-valid-successor-same-parent-fork",
        ),
        "RUST-083 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and 3/3 + 48/48 fail-closed matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust083",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 56',
            "expected 134 predecessor paths", "expected 137 RUST-083 paths",
            "axven-rust083-monitor-set-rotation.json",
            "axven-rust083-monitor-set-rotation-auth.json",
            "axven-rust083-successor-monitor-bundle.json",
            'test ! -e "$c/rust_083_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_set_rotation_fixture.py"',
        ),
        "RUST-083 workflow",
    )
    for forbidden in (
        "contents: write", "id-token: write", "packages: write", "pull-requests: write",
        "actions/upload-artifact", "attest", "release", "deploy",
    ):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, inherited-manifest bounded, read-only, and non-publishing")

    require(
        doc,
        (
            "TEST-ONLY", "M1/M2/M3", "M2/M3/M4", "2-of-3", "3/3", "48/48",
            "exact RUST-082 monitor-bundle SHA-256", "same-parent",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-083 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only rotation boundary")

    assert checks == 6
    print("RUST-083 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
