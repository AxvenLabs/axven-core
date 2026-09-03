#!/usr/bin/env python3
"""RUST-094 TEST-ONLY RUST-093 checkpoint monitor producer."""
from __future__ import annotations

import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_093_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_verify as journal_verify
import rust_094_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_verify as monitor_verify

OUT = Path("/tmp")
SEEDS = {
    monitor_verify.MONITOR_1_ID: "4b" * 32,
    monitor_verify.MONITOR_2_ID: "5b" * 32,
    monitor_verify.MONITOR_3_ID: "6b" * 32,
}


def private_for(monitor_id: str) -> Ed25519PrivateKey:
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[monitor_id]))
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if public != monitor_verify.PINNED_MONITORS[monitor_id]:
        raise AssertionError("RUST-094 TEST-only monitor public-key pin mismatch")
    return private


def signed_report(monitor_id: str, target: dict) -> dict:
    statement = {
        "schema": monitor_verify.STATEMENT_SCHEMA,
        "monitor_id": monitor_id,
        **target,
        "production": False,
    }
    return {
        "schema": monitor_verify.REPORT_SCHEMA,
        "algorithm": monitor_verify.ALGORITHM,
        "statement": statement,
        "signature": base64.b64encode(
            private_for(monitor_id).sign(monitor_verify.monitor_message(statement))
        ).decode("ascii"),
    }


def bundle(reports: list[dict]) -> dict:
    return {
        "schema": monitor_verify.BUNDLE_SCHEMA,
        "threshold": monitor_verify.THRESHOLD,
        "reports": sorted(reports, key=lambda report: report["statement"]["monitor_id"]),
        "production": False,
    }


def main() -> None:
    if len(sys.argv) != 2 or len(sys.argv[1]) != 40 or any(
        c not in "0123456789abcdef" for c in sys.argv[1]
    ):
        raise SystemExit(
            "usage: rust_094_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_fixture.py SOURCE_SHA"
        )
    source_sha = sys.argv[1]

    final_journal_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust093-final-monitor-rotation-journal.json",
        "RUST-093 final monitor rotation journal",
    )
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(
        OUT / "axven-rust093-final-monitor-rotation-checkpoint.json",
        "RUST-093 final monitor rotation checkpoint",
    )
    fork_checkpoint_raw, fork_checkpoint = floor_verify.load_canonical(
        OUT / "axven-rust093-observed-fork-monitor-rotation-checkpoint.json",
        "RUST-093 observed fork checkpoint",
    )

    final_statement = journal_verify.validate_checkpoint_envelope(
        final_checkpoint,
        final_journal_raw,
        journal_verify.rotation2_verify.FINAL_PINNED_MONITORS,
        "RUST-094 canonical final",
    )
    fork_statement = journal_verify.validate_checkpoint_envelope(
        fork_checkpoint,
        final_journal_raw,
        journal_verify.rotation2_verify.FINAL_PINNED_MONITORS,
        "RUST-094 observed fork",
    )
    target = monitor_verify.checkpoint_target(final_checkpoint_raw, final_statement)
    fork_target = monitor_verify.checkpoint_target(fork_checkpoint_raw, fork_statement)
    if target["activation_source_commit"] != source_sha:
        raise AssertionError("RUST-094 canonical target source mismatch")

    reports = [
        signed_report(monitor_id, target)
        for monitor_id in sorted(monitor_verify.PINNED_MONITORS)
    ]
    fork_report = signed_report(monitor_verify.MONITOR_3_ID, fork_target)

    (OUT / "axven-rust094-monitor-bundle.json").write_bytes(
        material_verify.canonical(bundle(reports))
    )
    (OUT / "axven-rust094-observed-fork-monitor-bundle.json").write_bytes(
        material_verify.canonical(bundle([reports[0], reports[1], fork_report]))
    )
    print("RUST-094 TEST-only RUST-093 journal checkpoint monitor fixture: GREEN")


if __name__ == "__main__":
    main()
