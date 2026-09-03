#!/usr/bin/env python3
"""RUST-096 static policy for TEST-ONLY second RUST-094 checkpoint monitor rotation."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_096.md"
VERIFY = ROOT / "rust_096_multistep_rust094_checkpoint_monitor_rotation_verify.py"
FIXTURE = ROOT / "rust_096_multistep_rust094_checkpoint_monitor_rotation_fixture.py"
SELFTEST = ROOT / "rust_096_multistep_rust094_checkpoint_monitor_rotation_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-rust096-multistep-checkpoint-monitor-rotation.yml"
BASE = ROOT / "rust_095_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_set_rotation_verify.py"
PREDECESSOR_WORKFLOW = ROOT / ".github/workflows/native-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-monitor-rotation-journal-monitor-rotation-journal-monitor-set-rotation.yml"
EXPECTED_RUST095_GIT_BLOB = "abcea7edbce750a97493875ce77dc437ffea7e04"
EXPECTED_RUST095_WORKFLOW_GIT_BLOB = "3d00ed9376dc0f968f0996b83a0aa2bda9ef7808"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_094_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_verify",
    "rust_095_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_set_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_094_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_verify",
    "rust_096_multistep_rust094_checkpoint_monitor_rotation_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST095_GIT_BLOB
    assert blob(PREDECESSOR_WORKFLOW.read_bytes()) == EXPECTED_RUST095_WORKFLOW_GIT_BLOB
    require(
        verify,
        (
            "import rust_095_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_set_rotation_verify as rotation1_verify",
        ),
        "RUST-096 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-095 verifier and workflow are pinned")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-096 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "PREDECESSOR_SET_SEQUENCE = 1", "FINAL_SET_SEQUENCE = 2",
            "CUMULATIVE_REVOKED_MONITOR_IDS", "monitor_verify.MONITOR_2_ID",
            "predecessor_rotation_sha256", "predecessor_rotation_auth_sha256",
            "predecessor_successor_bundle_sha256", "final_monitor_set_sequence",
            "final_monitor_set_sha256", "observed RUST-096 final same-parent checkpoint fork",
            "*monitor_verify.TARGET_KEYS",
        ),
        "RUST-096 verifier",
    )
    checks += 1
    print("[GREEN] second rotation continuity, cumulative revocation, 2-of-3 and target binding are fixed")

    require(
        fixture,
        (
            '"5b" * 32', '"6b" * 32', '"7b" * 32', '"8b" * 32',
            "Ed25519PrivateKey", "RUST-096 TEST-only monitor public-key pin mismatch",
        ),
        "RUST-096 producer fixture",
    )
    require(
        selftest,
        (
            "predecessor authorization availability: 3/3",
            "final monitoring availability: 3/3",
            "53/53 expected cases passed", "first-successor-replay",
            "observed-valid-final-same-parent-fork",
        ),
        "RUST-096 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and 3/3 + 3/3 + 53/53 test matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust096",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            'test ! -e "$c/rust_096_multistep_rust094_checkpoint_monitor_rotation_fixture.py"',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 69',
            "expected 170 RUST-095 paths", "expected 173 RUST-096 paths",
            "axven-rust096-final-monitor-bundle.json",
        ),
        "RUST-096 workflow",
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
            "TEST-ONLY", "M2/M3/M4 to M3/M4/M5", "2-of-3", "3/3", "53/53",
            "fixed 173-path manifest", "69-file verifier-only detached consumer",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-096 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only multi-step rotation boundary")

    assert checks == 6
    print("RUST-096 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
