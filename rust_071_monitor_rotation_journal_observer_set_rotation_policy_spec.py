#!/usr/bin/env python3
"""RUST-071 static policy for TEST-ONLY monitor-rotation-journal observer-set rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_071.md"
VERIFY = ROOT / "rust_071_monitor_rotation_journal_observer_set_rotation_verify.py"
FIXTURE = ROOT / "rust_071_monitor_rotation_journal_observer_set_rotation_fixture.py"
SELFTEST = ROOT / "rust_071_monitor_rotation_journal_observer_set_rotation_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-monitor-rotation-journal-observer-set-rotation.yml"
BASE = ROOT / "rust_070_monitor_rotation_journal_observer_verify.py"
EXPECTED_RUST070_GIT_BLOB = "5b4cee14f22c27cf582d1ef1190f9a8bf7669439"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_070_monitor_rotation_journal_observer_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_070_monitor_rotation_journal_observer_verify",
    "rust_071_monitor_rotation_journal_observer_set_rotation_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST070_GIT_BLOB
    require(
        verify,
        ("import rust_070_monitor_rotation_journal_observer_verify as observer_verify",),
        "RUST-071 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-070 verifier is composed")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-071 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "OLD_SET_SEQUENCE = 0", "NEW_SET_SEQUENCE = 1",
            'O4_ID = "rust-071-test-only-monitor-rotation-journal-observer-4-v1"',
            'O4_PUBLIC_KEY = bytes.fromhex("efe73e55679c12ea72d2584b9bf7e248f2266f8609381ca8b60cc369a5334a8d")',
            "REVOKED_OBSERVER_ID = observer_verify.OBSERVER_1_ID",
            "*observer_verify.TARGET_KEYS", "for key in observer_verify.TARGET_KEYS",
            "ids != sorted(ids)", "len(ids) != len(set(ids))",
            "observed successor same-parent RUST-069 monitor rotation journal checkpoint fork",
        ),
        "RUST-071 verifier",
    )
    checks += 1
    print("[GREEN] 2-of-3 rotation, revocation, full-target binding and split-view rejection are fixed")

    require(
        fixture,
        (
            '"c9" * 32', '"d9" * 32', '"e9" * 32', '"f9" * 32',
            "Ed25519PrivateKey", "RUST-071 TEST-only monitor-rotation-journal observer public-key pin mismatch",
        ),
        "RUST-071 producer fixture",
    )
    require(
        selftest,
        (
            "3/3 valid two-observer subsets accepted", "49/49 expected cases passed",
            "old-rust070-bundle-replay", "observed-valid-successor-same-parent-fork",
        ),
        "RUST-071 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and 49-case authorization/availability/fork matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "for n in $(seq -w 36 71)",
            'chmod 0444 "${files[@]}"', "for f in /tmp/axven-rust071-*.json",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            'test ! -e "$c/rust_071_monitor_rotation_journal_observer_set_rotation_fixture.py"',
            'test "$(wc -l < /tmp/axven-rust071-paths)" -eq 104',
        ),
        "RUST-071 workflow",
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
            "O1/O2/O3 -> O2/O3/O4", "O1 is explicitly revoked",
            "3/3 valid two-observer authorization subsets", "3/3 valid two-observer successor subsets",
            "every field in the complete inherited RUST-070 canonical checkpoint target",
            "same monitor-set sequence and same previous-checkpoint parent",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-071 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only observer administration boundary")

    assert checks == 6
    print("RUST-071 monitor-rotation-journal observer-set rotation static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
