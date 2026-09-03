#!/usr/bin/env python3
"""RUST-085 static policy for TEST-ONLY append-only monitor rotation journal."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOC = ROOT / "RUST_085.md"
VERIFY = ROOT / "rust_085_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_verify.py"
FIXTURE = ROOT / "rust_085_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_fixture.py"
SELFTEST = ROOT / "rust_085_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal.yml"
BASE = ROOT / "rust_084_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_verify.py"
PREDECESSOR_WORKFLOW = ROOT / ".github/workflows/native-multistep-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-observer-rotation-journal-monitor-rotation.yml"
EXPECTED_RUST084_GIT_BLOB = "72bba40a1a523e7966572594bf4ea9160d008fe0"
EXPECTED_RUST084_WORKFLOW_GIT_BLOB = "45252e53dcc04cf938b44e98edb03372153ab488"

ALLOWED_VERIFY_IMPORTS = {
    "__future__", "hashlib", "pathlib", "sys",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_082_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_verify",
    "rust_083_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_set_rotation_verify",
    "rust_084_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_verify",
}
ALLOWED_SELFTEST_IMPORTS = {
    "__future__", "base64", "copy", "itertools", "json", "pathlib", "sys", "tempfile",
    "rust_030_stdlib_material_verify", "rust_032_external_monotonic_floor_verify",
    "rust_082_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_verify",
    "rust_085_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_verify",
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

    assert blob(BASE.read_bytes()) == EXPECTED_RUST084_GIT_BLOB
    assert blob(PREDECESSOR_WORKFLOW.read_bytes()) == EXPECTED_RUST084_WORKFLOW_GIT_BLOB
    require(
        verify,
        ("import rust_084_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_verify as rotation2_verify",),
        "RUST-085 verifier composition",
    )
    checks += 1
    print("[GREEN] exact reviewed RUST-084 verifier and workflow are pinned")

    assert imported_roots(verify) <= ALLOWED_VERIFY_IMPORTS
    assert imported_roots(selftest) <= ALLOWED_SELFTEST_IMPORTS
    for forbidden in (
        "cryptography", "Ed25519PrivateKey", "SEEDS =", ".sign(", "subprocess",
        "requests", "urllib", "socket", "import axven", "from axven",
    ):
        assert forbidden not in verify and forbidden not in selftest, forbidden
    checks += 1
    print("[GREEN] detached RUST-085 verifier/selftest have no signing or network capability")

    require(
        verify,
        (
            "THRESHOLD = 2", "target_digest", "predecessor_entry_sha256",
            "cumulative_revoked_monitor_ids", "final RUST-085 monitor rotation journal rewrites checkpointed prefix",
            "observed same-parent RUST-085 monitor rotation journal checkpoint fork",
            "rotation1_verify.NEW_PINNED_MONITORS", "rotation2_verify.FINAL_PINNED_MONITORS",
            "base_paths[132]", "base_paths[133]", "base_paths[139]",
        ),
        "RUST-085 verifier",
    )
    checks += 1
    print("[GREEN] append-only hash chain, exact target/evidence binding, quorum, and fork rejection are fixed")

    require(
        fixture,
        (
            '"69" * 32', '"79" * 32', '"89" * 32', '"99" * 32',
            "Ed25519PrivateKey", "RUST-085 TEST-only journal monitor public-key pin mismatch",
        ),
        "RUST-085 producer fixture",
    )
    require(
        selftest,
        (
            "prefix checkpoint availability: 3/3 valid two-monitor subsets accepted",
            "final checkpoint availability: 3/3 valid two-monitor subsets accepted",
            "35/35 expected cases passed",
            "observed-valid-same-parent-monitor-rotation-journal-fork",
        ),
        "RUST-085 selftest",
    )
    checks += 1
    print("[GREEN] producer-only keys and 3/3 + 35/35 availability/fork matrix are fixed")

    require(
        workflow,
        (
            "permissions:\n  contents: read", "persist-credentials: false",
            'python-version: "3.13.15"', "chmod 0444", "axven-rust085",
            "env -i HOME=/tmp PATH=/usr/bin:/bin", "/usr/bin/python3 -S",
            'test ! -e "$c/rust_085_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_fixture.py"',
            'test "$(wc -l < /tmp/axven-rust085-paths)" -eq 144',
            'test "$(find "$c" -maxdepth 1 -type f | wc -l)" -eq 58',
            "expected 140 RUST-084 paths", "expected 144 RUST-085 paths",
        ),
        "RUST-085 workflow",
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
            "M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5", "cumulative revocation `[M1, M2]`",
            "2-of-3", "3/3 valid two-monitor subsets", "35/35 fail-closed",
            "same-parent split view", "144-path", "Production consensus remains Python-authoritative.",
        ),
        "RUST-085 documentation",
    )
    checks += 1
    print("[GREEN] documentation preserves TEST-only journal boundary")

    assert checks == 6
    print("RUST-085 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
