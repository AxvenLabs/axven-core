#!/usr/bin/env python3
"""RUST-115 static policy for TEST-ONLY RUST-114 checkpoint monitor-set rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_115.md"
VERIFY = ROOT / "rust_115_rust102_checkpoint_monitor_rotation_verify.py"
FIXTURE = ROOT / "rust_115_rust102_checkpoint_monitor_rotation_fixture.py"
SELFTEST = ROOT / "rust_115_rust102_checkpoint_monitor_rotation_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-rust115-rust102-checkpoint-monitor-rotation.yml"
BASE = ROOT / "rust_114_rust113_checkpoint_monitor_verify.py"
PREDECESSOR_WORKFLOW = ROOT / ".github/workflows/native-rust114-rust113-checkpoint-monitor.yml"
EXPECTED_RUST114_GIT_BLOB = "22b1bcad60b54ba2e4038ede6d4cb64a984dbfc7"
EXPECTED_RUST114_WORKFLOW_GIT_BLOB = "d8f3f090d9033d519b0cc787734e451eea79039e"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_114_rust113_checkpoint_monitor_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_114_rust113_checkpoint_monitor_verify",
    "rust_115_rust102_checkpoint_monitor_rotation_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST114_GIT_BLOB
    assert blob(PREDECESSOR_WORKFLOW.read_bytes()) == EXPECTED_RUST114_WORKFLOW_GIT_BLOB
    require(
        verify,
        ("import rust_114_rust113_checkpoint_monitor_verify as monitor_verify",),
        "RUST-115 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-114 verifier and workflow are pinned")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-115 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "OLD_SET_SEQUENCE = 0", "NEW_SET_SEQUENCE = 1",
            "REVOKED_MONITOR_ID = monitor_verify.MONITOR_1_ID",
            "predecessor_monitor_bundle_sha256", "successor_monitor_set_sequence",
            "successor_monitor_set_sha256", "observed RUST-115 successor same-parent checkpoint fork",
            "*monitor_verify.TARGET_KEYS", "base_paths[220]",
        ),
        "RUST-115 verifier",
    )
    checks += 1
    print("[GREEN] exact predecessor binding, 2-of-3 rotation, revocation, and successor epoch are fixed")

    require(
        fixture,
        (
            '"dc" * 32', '"ec" * 32', '"fc" * 32', '"0d" * 32',
            "Ed25519PrivateKey", "RUST-115 TEST-only monitor public-key pin mismatch",
        ),
        "RUST-115 producer fixture",
    )
    require(
        selftest,
        (
            "predecessor authorization availability: 3/3",
            "successor monitoring availability: 3/3",
            "50/50 expected cases passed", "old-rust102-bundle-replay",
            "observed-valid-successor-same-parent-fork",
        ),
        "RUST-115 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and 3/3 + 3/3 + 50/50 test matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust115",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            '"rust_*.py"', '"RUST_*.md"', 'printf -v n3 "%03d" "$n"',
            'test ! -e "$c/rust_115_rust102_checkpoint_monitor_rotation_fixture.py"',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 88',
            "expected 189 RUST-114 paths", "expected 192 RUST-115 paths",
            "axven-rust115-successor-monitor-bundle.json",
        ),
        "RUST-115 workflow",
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
            "TEST-ONLY", "M1/M2/M3 to M2/M3/M4", "2-of-3", "3/3", "50/50",
            "fixed 192-path manifest", "76-file verifier-only detached consumer",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-115 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only monitor rotation boundary")

    assert checks == 6
    print("RUST-115 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
