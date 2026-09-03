#!/usr/bin/env python3
"""RUST-099 static policy for TEST-ONLY RUST-098 checkpoint monitor-set rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_099.md"
VERIFY = ROOT / "rust_099_rust098_checkpoint_monitor_rotation_verify.py"
FIXTURE = ROOT / "rust_099_rust098_checkpoint_monitor_rotation_fixture.py"
SELFTEST = ROOT / "rust_099_rust098_checkpoint_monitor_rotation_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-rust099-rust098-checkpoint-monitor-rotation.yml"
BASE = ROOT / "rust_098_rust097_checkpoint_monitor_verify.py"
PREDECESSOR_WORKFLOW = ROOT / ".github/workflows/native-rust098-rust097-checkpoint-monitor.yml"
EXPECTED_RUST098_GIT_BLOB = "43aceec70be79333ee6894a960cd895e7952fcb6"
EXPECTED_RUST098_WORKFLOW_GIT_BLOB = "1cf12ce8a7e7a282c6b63329577f9a300a0461e0"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_098_rust097_checkpoint_monitor_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_098_rust097_checkpoint_monitor_verify",
    "rust_099_rust098_checkpoint_monitor_rotation_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST098_GIT_BLOB
    assert blob(PREDECESSOR_WORKFLOW.read_bytes()) == EXPECTED_RUST098_WORKFLOW_GIT_BLOB
    require(
        verify,
        ("import rust_098_rust097_checkpoint_monitor_verify as monitor_verify",),
        "RUST-099 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-098 verifier and workflow are pinned")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-099 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "OLD_SET_SEQUENCE = 0", "NEW_SET_SEQUENCE = 1",
            "REVOKED_MONITOR_ID = monitor_verify.MONITOR_1_ID",
            "predecessor_monitor_bundle_sha256", "successor_monitor_set_sequence",
            "successor_monitor_set_sha256", "observed RUST-099 successor same-parent checkpoint fork",
            "*monitor_verify.TARGET_KEYS",
        ),
        "RUST-099 verifier",
    )
    checks += 1
    print("[GREEN] exact predecessor binding, 2-of-3 rotation, revocation, and successor epoch are fixed")

    require(
        fixture,
        (
            '"9b" * 32', '"ab" * 32', '"bb" * 32', '"cb" * 32',
            "Ed25519PrivateKey", "RUST-099 TEST-only monitor public-key pin mismatch",
        ),
        "RUST-099 producer fixture",
    )
    require(
        selftest,
        (
            "predecessor authorization availability: 3/3",
            "successor monitoring availability: 3/3",
            "50/50 expected cases passed", "old-rust098-bundle-replay",
            "observed-valid-successor-same-parent-fork",
        ),
        "RUST-099 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and 3/3 + 3/3 + 50/50 test matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust099",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            'test ! -e "$c/rust_099_rust098_checkpoint_monitor_rotation_fixture.py"',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 72',
            "expected 178 RUST-098 paths", "expected 181 RUST-099 paths",
            "axven-rust099-successor-monitor-bundle.json",
        ),
        "RUST-099 workflow",
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
            "TEST-ONLY", "M1/M2/M3 to M2/M3/M4", "2-of-3", "3/3", "50/50",
            "fixed 181-path manifest", "72-file verifier-only detached consumer",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-099 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only monitor rotation boundary")

    assert checks == 6
    print("RUST-099 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
