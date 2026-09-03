#!/usr/bin/env python3
"""RUST-088 static policy for TEST-ONLY second monitor-set rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_088.md"
VERIFY = ROOT / "rust_088_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_verify.py"
FIXTURE = ROOT / "rust_088_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_fixture.py"
SELFTEST = ROOT / "rust_088_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-multistep-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-monitor-rotation.yml"
BASE = ROOT / "rust_087_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_set_rotation_verify.py"
PREDECESSOR_WORKFLOW = ROOT / ".github/workflows/native-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-monitor-set-rotation.yml"
EXPECTED_RUST087_GIT_BLOB = "68f501c2455420fd4f94b43e706f4f94b14c0b97"
EXPECTED_RUST087_WORKFLOW_GIT_BLOB = "94b5cf45c618e4b678efecadd37f5bcad4b79d89"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_086_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_verify",
    "rust_087_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_set_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_086_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_verify",
    "rust_088_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST087_GIT_BLOB
    assert blob(PREDECESSOR_WORKFLOW.read_bytes()) == EXPECTED_RUST087_WORKFLOW_GIT_BLOB
    require(
        verify,
        ("import rust_087_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_set_rotation_verify as rotation1_verify",),
        "RUST-088 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-087 verifier and workflow are pinned")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-088 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "PREDECESSOR_SET_SEQUENCE = 1", "FINAL_SET_SEQUENCE = 2",
            "CUMULATIVE_REVOKED_MONITOR_IDS", "predecessor_rotation_sha256",
            "predecessor_rotation_auth_sha256", "predecessor_successor_bundle_sha256",
            "*monitor_verify.TARGET_KEYS", "final_monitor_set_sequence",
            "final_monitor_set_sha256", "observed RUST-088 final same-parent checkpoint fork",
            "production second monitor rotation forbidden in RUST-088",
        ),
        "RUST-088 verifier",
    )
    checks += 1
    print("[GREEN] second-rotation continuity, 12-field target binding, namespaced final epoch, revocation, and fork rejection are fixed")

    require(
        fixture,
        ('"ba" * 32', '"ca" * 32', '"da" * 32', '"ea" * 32', "Ed25519PrivateKey"),
        "RUST-088 producer fixture",
    )
    require(
        selftest,
        (
            "3/3 valid two-monitor subsets accepted", "53/53 expected cases passed",
            "revoked-m1-resurrection", "revoked-m2-resurrection",
            "first-successor-replay", "final-statement-set-sequence",
            "final-statement-set-digest", "observed-valid-final-same-parent-fork",
        ),
        "RUST-088 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and 3/3 + 3/3 + 53/53 fail-closed matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust088",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 61',
            "expected 148 RUST-087 paths", "expected 151 RUST-088 paths",
            "axven-rust088-second-monitor-set-rotation.json",
            "axven-rust088-second-monitor-set-rotation-auth.json",
            "axven-rust088-final-monitor-bundle.json",
            'test ! -e "$c/rust_088_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_fixture.py"',
        ),
        "RUST-088 workflow",
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
            "TEST-ONLY", "M2/M3/M4", "M3/M4/M5", "2-of-3", "3/3", "53/53",
            "cumulative revocation", "RUST-087 first rotation",
            "final_monitor_set_sequence", "same-parent",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-088 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only second-rotation boundary")

    assert checks == 6
    print("RUST-088 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
