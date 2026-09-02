#!/usr/bin/env python3
"""Static policy contract for RUST-058 TEST-ONLY checkpoint monitoring."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent

DOC = ROOT / "RUST_058.md"
VERIFY = ROOT / "rust_058_observer_rotation_journal_monitor_verify.py"
FIXTURE = ROOT / "rust_058_observer_rotation_journal_monitor_fixture.py"
SELFTEST = ROOT / "rust_058_observer_rotation_journal_monitor_selftest.py"
WORKFLOW = ROOT / ".github/workflows/native-journal-monitor-journal-observer-rotation-journal-monitor.yml"


def text(path: Path) -> str:
    value = path.read_text(encoding="utf-8")
    if "\r" in value:
        raise AssertionError(f"CR forbidden: {path.name}")
    return value


def require(haystack: str, needles: tuple[str, ...], label: str) -> None:
    missing = [needle for needle in needles if needle not in haystack]
    if missing:
        raise AssertionError(f"{label} missing required markers: {missing}")


def forbid(haystack: str, needles: tuple[str, ...], label: str) -> None:
    found = [needle for needle in needles if needle in haystack]
    if found:
        raise AssertionError(f"{label} contains forbidden markers: {found}")


def main() -> None:
    doc = text(DOC)
    verify = text(VERIFY)
    fixture = text(FIXTURE)
    selftest = text(SELFTEST)
    workflow = text(WORKFLOW)

    require(
        doc,
        (
            "TEST-ONLY",
            "2-of-3",
            "3/3",
            "exact RUST-057 final observer-rotation-journal checkpoint SHA-256",
            "same-parent",
            "Production consensus remains Python-authoritative.",
        ),
        "RUST-058 documentation",
    )
    print("[GREEN] RUST-058 documentation boundary")

    require(
        verify,
        (
            'THRESHOLD = 2',
            'production observer-rotation-journal monitoring forbidden in RUST-058',
            'observed monitor same-parent observer-rotation-journal checkpoint fork',
            'activation_source_commit',
            'observer_rotation_journal_checkpoint_statement_sha256',
        ),
        "RUST-058 verifier",
    )
    print("[GREEN] RUST-058 verifier policy markers")

    require(
        fixture,
        ("Ed25519PrivateKey", "SEEDS =", "RUST-058 TEST-only monitor public-key pin mismatch"),
        "RUST-058 producer fixture",
    )
    forbid(
        verify + selftest,
        ("Ed25519PrivateKey", "SEEDS =", "socket.", "requests.", "urllib."),
        "RUST-058 detached consumer",
    )
    print("[GREEN] RUST-058 producer/consumer signing separation")

    require(
        workflow,
        (
            "permissions:\n  contents: read",
            "persist-credentials: false",
            "chmod 0444 /tmp/axven-rust058-*.json",
            "env -i HOME=/tmp PATH=/usr/bin:/bin",
            "/usr/bin/python3 -S",
            "rust_058_observer_rotation_journal_monitor_selftest.py",
        ),
        "RUST-058 workflow",
    )
    forbid(
        workflow,
        ("contents: write", "id-token: write", "packages: write", "pull-requests: write"),
        "RUST-058 workflow permissions",
    )
    print("[GREEN] RUST-058 workflow read-only/detached boundary")

    require(
        selftest,
        (
            "3/3 valid two-monitor subsets accepted",
            "signed observed same-parent fork evidence validated",
            "29/29 expected cases passed",
            "rust057-checkpoint-replay",
        ),
        "RUST-058 fail-closed selftest",
    )
    print("[GREEN] RUST-058 availability/replay/fork policy")

    require(
        verify,
        (
            "journal_observer_checkpoint_sha256",
            "monitor_journal_checkpoint_sha256",
            "monitor_journal_checkpoint_statement_sha256",
            "observed_checkpoint_sha256",
            "observed_checkpoint_statement_sha256",
        ),
        "RUST-058 inherited checkpoint binding",
    )
    print("[GREEN] RUST-058 inherited checkpoint binding")

    print("RUST-058 static policy: 6/6 checks passed")


if __name__ == "__main__":
    main()
