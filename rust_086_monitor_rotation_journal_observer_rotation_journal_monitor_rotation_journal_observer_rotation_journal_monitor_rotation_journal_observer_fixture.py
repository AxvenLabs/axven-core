#!/usr/bin/env python3
"""RUST-086 TEST-ONLY RUST-085 journal checkpoint observer producer."""
from __future__ import annotations

import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_084_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_verify as rotation2_verify
import rust_085_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_verify as journal_verify
import rust_086_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_verify as observer_verify

OUT = Path("/tmp")
SEEDS = {
    observer_verify.OBSERVER_1_ID: "a9" * 32,
    observer_verify.OBSERVER_2_ID: "b9" * 32,
    observer_verify.OBSERVER_3_ID: "c9" * 32,
}


def signed_report(observer_id: str, target: dict) -> dict:
    statement = {
        "schema": observer_verify.STATEMENT_SCHEMA,
        "observer_id": observer_id,
        **target,
        "production": False,
    }
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[observer_id]))
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if public != observer_verify.PINNED_OBSERVERS[observer_id]:
        raise AssertionError("RUST-086 TEST-only journal checkpoint observer public-key pin mismatch")
    return {
        "schema": observer_verify.REPORT_SCHEMA,
        "algorithm": observer_verify.ALGORITHM,
        "statement": statement,
        "signature": base64.b64encode(
            private.sign(observer_verify.observation_message(statement))
        ).decode("ascii"),
    }


def bundle(reports: list[dict]) -> dict:
    return {
        "schema": observer_verify.BUNDLE_SCHEMA,
        "threshold": observer_verify.THRESHOLD,
        "reports": sorted(reports, key=lambda report: report["statement"]["observer_id"]),
        "production": False,
    }


def main() -> None:
    if len(sys.argv) != 2 or len(sys.argv[1]) != 40 or any(
        c not in "0123456789abcdef" for c in sys.argv[1]
    ):
        raise SystemExit(
            "usage: rust_086_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_fixture.py SOURCE_SHA"
        )
    source_sha = sys.argv[1]

    final_journal_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust085-final-monitor-rotation-journal.json",
        "RUST-085 final monitor rotation journal",
    )
    checkpoint_raw, checkpoint = floor_verify.load_canonical(
        OUT / "axven-rust085-final-monitor-rotation-checkpoint.json",
        "RUST-085 final monitor rotation checkpoint",
    )
    fork_raw, fork_checkpoint = floor_verify.load_canonical(
        OUT / "axven-rust085-observed-fork-monitor-rotation-checkpoint.json",
        "RUST-085 observed fork monitor rotation checkpoint",
    )

    journal_verify.validate_checkpoint_envelope(
        checkpoint,
        final_journal_raw,
        rotation2_verify.FINAL_PINNED_MONITORS,
        "RUST-086 canonical final",
    )
    journal_verify.validate_checkpoint_envelope(
        fork_checkpoint,
        final_journal_raw,
        rotation2_verify.FINAL_PINNED_MONITORS,
        "RUST-086 observed fork",
    )

    target = observer_verify.canonical_target(checkpoint_raw, checkpoint, source_sha)
    fork_target = observer_verify.canonical_target(fork_raw, fork_checkpoint, source_sha)
    reports = [signed_report(observer_id, target) for observer_id in sorted(SEEDS)]
    fork_report = signed_report(observer_verify.OBSERVER_3_ID, fork_target)

    (OUT / "axven-rust086-monitor-rotation-journal-observer-bundle.json").write_bytes(
        material_verify.canonical(bundle(reports))
    )
    (OUT / "axven-rust086-observed-fork-observer-bundle.json").write_bytes(
        material_verify.canonical(bundle([reports[0], reports[1], fork_report]))
    )
    print("RUST-086 TEST-only RUST-085 journal checkpoint observation fixture: GREEN")


if __name__ == "__main__":
    main()
