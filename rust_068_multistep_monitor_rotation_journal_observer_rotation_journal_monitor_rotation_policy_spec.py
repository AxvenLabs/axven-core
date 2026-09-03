#!/usr/bin/env python3
"""RUST-068 static policy for TEST-ONLY multi-step monitor rotation continuity."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_068.md"
VERIFY = ROOT / "rust_068_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_verify.py"
FIXTURE = ROOT / "rust_068_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_fixture.py"
SELFTEST = ROOT / "rust_068_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-multistep-monitor-rotation-journal-observer-rotation-journal-monitor-rotation.yml"
BASE = ROOT / "rust_067_monitor_rotation_journal_observer_rotation_journal_monitor_set_rotation_verify.py"
EXPECTED_RUST067_GIT_BLOB = "86b588b6639ee0515c9c20d21df40734d6825de6"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_066_monitor_rotation_journal_observer_rotation_journal_monitor_verify",
    "rust_067_monitor_rotation_journal_observer_rotation_journal_monitor_set_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_066_monitor_rotation_journal_observer_rotation_journal_monitor_verify",
    "rust_068_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST067_GIT_BLOB
    require(
        verify,
        ("import rust_067_monitor_rotation_journal_observer_rotation_journal_monitor_set_rotation_verify as rotation1_verify",),
        "RUST-068 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-067 verifier is composed")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-068 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "PREDECESSOR_SET_SEQUENCE = 1", "FINAL_SET_SEQUENCE = 2",
            "CUMULATIVE_REVOKED_MONITOR_IDS", "*monitor_verify.TARGET_KEYS",
            "predecessor_rotation_sha256", "predecessor_rotation_auth_sha256",
            "predecessor_successor_bundle_sha256",
            "production second monitor rotation forbidden in RUST-068",
            "observed RUST-068 final same-parent checkpoint fork",
        ),
        "RUST-068 verifier",
    )
    checks += 1
    print("[GREEN] full inherited target, predecessor digests, cumulative revocation, and fork rejection are fixed")

    require(
        fixture,
        (
            '"89" * 32', '"99" * 32', '"a9" * 32', '"b9" * 32',
            "Ed25519PrivateKey", "RUST-068 TEST-only monitor public-key pin mismatch",
        ),
        "RUST-068 producer fixture",
    )
    require(
        selftest,
        (
            "3/3 valid two-monitor subsets accepted",
            "51/51 expected cases passed",
            "first-successor-replay",
            "observed-valid-final-same-parent-fork",
        ),
        "RUST-068 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and 51-case availability/replay/fork matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust068",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            'test ! -e "$c/rust_068_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_fixture.py"',
            'test "$(wc -l < /tmp/axven-rust068-paths)" -eq 96',
        ),
        "RUST-068 workflow",
    )
    for forbidden in (
        "contents: write", "id-token: write", "packages: write", "pull-requests: write",
        "actions/upload-artifact", "attest", "release", "deploy",
    ):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, and non-publishing")

    require(
        doc,
        (
            "M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5",
            "M1 remains revoked and M2 is newly revoked", "cumulative revocation `[M1, M2]`",
            "2-of-3", "3/3 valid two-monitor authorization subsets",
            "complete inherited RUST-066 canonical checkpoint target", "same-parent split views",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-068 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only multi-step rotation boundary")

    assert checks == 6
    print("RUST-068 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
