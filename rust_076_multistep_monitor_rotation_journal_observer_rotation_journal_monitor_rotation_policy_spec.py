#!/usr/bin/env python3
"""RUST-076 static policy for TEST-ONLY second monitor rotation continuity."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_076.md"
VERIFY = ROOT / "rust_076_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_verify.py"
FIXTURE = ROOT / "rust_076_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_fixture.py"
SELFTEST = ROOT / "rust_076_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-multistep-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-v2.yml"
BASE = ROOT / "rust_075_monitor_rotation_journal_observer_rotation_journal_monitor_set_rotation_verify.py"
EXPECTED_RUST075_GIT_BLOB = "0adad2e94f6f6d44622cba43f46617b086f9a4d7"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_074_monitor_rotation_journal_observer_rotation_journal_monitor_verify",
    "rust_075_monitor_rotation_journal_observer_rotation_journal_monitor_set_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_074_monitor_rotation_journal_observer_rotation_journal_monitor_verify",
    "rust_076_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST075_GIT_BLOB
    require(
        verify,
        ("import rust_075_monitor_rotation_journal_observer_rotation_journal_monitor_set_rotation_verify as rotation1_verify",),
        "RUST-076 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-075 verifier is composed")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-076 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "PREDECESSOR_SET_SEQUENCE = 1", "FINAL_SET_SEQUENCE = 2",
            "CUMULATIVE_REVOKED_MONITOR_IDS",
            "predecessor_rotation_sha256", "predecessor_rotation_auth_sha256",
            "predecessor_successor_bundle_sha256", "*monitor_verify.TARGET_KEYS",
            "production second monitor rotation forbidden in RUST-076",
            "observed RUST-076 final same-parent checkpoint fork",
        ),
        "RUST-076 verifier",
    )
    checks += 1
    print("[GREEN] multi-step continuity, cumulative revocation, full target binding, and fork rejection are fixed")

    require(
        fixture,
        (
            '"b9" * 32', '"c9" * 32', '"d9" * 32', '"e9" * 32',
            "Ed25519PrivateKey", "RUST-076 TEST-only monitor public-key pin mismatch",
        ),
        "RUST-076 producer fixture",
    )
    require(
        selftest,
        (
            "3/3 valid two-monitor subsets accepted",
            "51/51 expected cases passed",
            "first-successor-replay",
            "observed-valid-final-same-parent-fork",
            "revoked-m1-resurrection", "revoked-m2-resurrection",
        ),
        "RUST-076 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and 51-case availability/replay/fork matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust076",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            'test ! -e "$c/rust_076_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_fixture.py"',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 49',
            'test "$(wc -l < /tmp/axven-rust076-paths)" -eq 118',
        ),
        "RUST-076 workflow",
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
            "M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5", "M2 is newly revoked",
            "2-of-3", "3/3 valid two-monitor authorization subsets",
            "complete inherited RUST-074 canonical checkpoint target", "same-parent final split view",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-076 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only multi-step rotation boundary")

    assert checks == 6
    print("RUST-076 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
