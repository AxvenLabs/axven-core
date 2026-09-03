#!/usr/bin/env python3
"""RUST-072 static policy for TEST-ONLY multi-step observer-set rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-multistep-monitor-rotation-journal-observer-set-rotation.yml"
VERIFIER = ROOT / "rust_072_multistep_monitor_rotation_journal_observer_set_rotation_verify.py"
SELFTEST = ROOT / "rust_072_multistep_monitor_rotation_journal_observer_set_rotation_selftest.py"
FIXTURE = ROOT / "rust_072_multistep_monitor_rotation_journal_observer_set_rotation_fixture.py"
BASE = ROOT / "rust_071_monitor_rotation_journal_observer_set_rotation_verify.py"
DOC = ROOT / "RUST_072.md"
EXPECTED_RUST071_GIT_BLOB = "764981a52d38c59ae11b588090ed82b4f04ee212"

ALLOWED_VERIFIER_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_070_monitor_rotation_journal_observer_verify",
    "rust_071_monitor_rotation_journal_observer_set_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_070_monitor_rotation_journal_observer_verify",
    "rust_072_multistep_monitor_rotation_journal_observer_set_rotation_verify",
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
    verifier = text(VERIFIER); selftest = text(SELFTEST); fixture = text(FIXTURE)
    workflow = text(WORKFLOW); doc = text(DOC); checks = 0

    assert blob(BASE.read_bytes()) == EXPECTED_RUST071_GIT_BLOB
    require(
        verifier,
        ("import rust_071_monitor_rotation_journal_observer_set_rotation_verify as rotation1_verify",),
        "RUST-072 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-071 verifier is composed")

    assert imported_roots(verifier) <= ALLOWED_VERIFIER_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verifier and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-072 verifier/selftest have no signing or network capability")

    require(
        verifier,
        (
            "THRESHOLD = 2", "PREDECESSOR_SET_SEQUENCE = 1", "FINAL_SET_SEQUENCE = 2",
            'O5_ID = "rust-072-test-only-monitor-rotation-journal-observer-5-v1"',
            'O5_PUBLIC_KEY = bytes.fromhex("fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618")',
            "CUMULATIVE_REVOKED_OBSERVER_IDS", "predecessor_rotation_sha256",
            "predecessor_rotation_auth_sha256", "predecessor_successor_bundle_sha256",
            "for key in TARGET_KEYS", "ids != sorted(ids)", "len(ids) != len(set(ids))",
            "observed RUST-072 final same-parent checkpoint fork",
        ),
        "RUST-072 verifier",
    )
    checks += 1
    print("[GREEN] cumulative revocation, full target binding, pins and split-view rejection are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "env -i HOME=/tmp PATH=/usr/bin:/bin",
            "/usr/bin/python3 -S", 'for n in $(seq -w 36 72)',
            'test ! -e "$c/rust_072_multistep_monitor_rotation_journal_observer_set_rotation_fixture.py"',
            'test "$(wc -l < /tmp/axven-rust072-paths)" -eq 107',
        ),
        "RUST-072 workflow",
    )
    for forbidden in (
        "contents: write", "id-token: write", "packages: write", "pull-requests: write",
        "actions/upload-artifact", "attest", "release", "deploy",
    ):
        assert forbidden not in workflow.lower(), forbidden
    checks += 1
    print("[GREEN] workflow stays detached, read-only, manifest-bounded and non-publishing")

    require(
        fixture,
        (
            '"d9" * 32', '"e9" * 32', '"f9" * 32', '"09" * 32',
            "Ed25519PrivateKey", "RUST-072 TEST-only observer public-key pin mismatch",
        ),
        "RUST-072 producer fixture",
    )
    require(
        selftest,
        (
            "3/3 valid two-observer subsets accepted",
            "51/51 expected cases passed", "first-successor-replay",
            "observed-valid-final-same-parent-fork",
        ),
        "RUST-072 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and 51-case multi-step fail-closed matrix are fixed")

    require(
        doc,
        (
            "O1/O2/O3 -> O2/O3/O4 -> O3/O4/O5", "cumulative revocation `[O1, O2]`",
            "at least 2-of-3", "3/3 valid two-observer", "same monitor-set sequence",
            "split-view safety over availability", "does **not** create global network gossip",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-072 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only multi-step rotation boundary")

    assert checks == 6
    print("RUST-072 multi-step observer rotation static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
