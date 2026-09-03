#!/usr/bin/env python3
"""RUST-080 static policy for TEST-ONLY multi-step RUST-077 checkpoint observer rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_080.md"
VERIFY = ROOT / "rust_080_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_verify.py"
FIXTURE = ROOT / "rust_080_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_fixture.py"
SELFTEST = ROOT / "rust_080_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-multistep-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-observer-rotation.yml"
BASE = ROOT / "rust_079_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify.py"
EXPECTED_RUST079_GIT_BLOB = "ea4a268bde26d71a7b74853fd32fbdf0f1b14891"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_078_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_verify",
    "rust_079_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_078_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_verify",
    "rust_080_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST079_GIT_BLOB
    require(
        verify,
        ("import rust_079_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify as rotation1_verify",),
        "RUST-080 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-079 verifier is composed")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-080 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "PREDECESSOR_SET_SEQUENCE = 1", "FINAL_SET_SEQUENCE = 2",
            "O5_PUBLIC_KEY", "CUMULATIVE_REVOKED_OBSERVER_IDS",
            "predecessor_rotation_sha256", "predecessor_rotation_auth_sha256",
            "predecessor_successor_bundle_sha256", "*observer_verify.TARGET_KEYS",
            "observed RUST-080 final same-parent RUST-077 checkpoint fork",
        ),
        "RUST-080 verifier",
    )
    checks += 1
    print("[GREEN] multi-step rotation, cumulative revocation, predecessor digests, full target binding, and fork rejection are fixed")

    require(
        fixture,
        (
            '"19" * 32', '"29" * 32', '"39" * 32', '"49" * 32',
            "Ed25519PrivateKey", "RUST-080 TEST-only observer public-key pin mismatch",
        ),
        "RUST-080 producer fixture",
    )
    require(
        selftest,
        (
            "predecessor authorization availability: 3/3 valid two-observer subsets accepted",
            "final observation availability: 3/3 valid two-observer subsets accepted",
            "51/51 expected cases passed", "revoked-o1-resurrection", "revoked-o2-resurrection",
            "first-successor-replay", "observed-valid-final-same-parent-fork",
        ),
        "RUST-080 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and 51-case multi-step/replay/fork matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust080",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            'test ! -e "$c/rust_080_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_fixture.py"',
            'test "$(wc -l < /tmp/axven-rust080-paths)" -eq 129',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 53',
        ),
        "RUST-080 workflow",
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
            "O2/O3/O4", "O3/O4/O5", "2-of-3", "cumulative revocation is `[O1, O2]`",
            "3/3 valid two-observer", "51/51 fail-closed cases",
            "all 12 canonical RUST-077 final checkpoint target fields",
            "same-parent RUST-077 checkpoint fork", "Production consensus remains Python-authoritative.",
        ),
        "RUST-080 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only multi-step observer rotation boundary")

    assert checks == 6
    print("RUST-080 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
