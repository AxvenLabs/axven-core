#!/usr/bin/env python3
"""RUST-046 TEST-ONLY journal-observer producer. Private seeds stay producer-side."""
from __future__ import annotations

import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_044_multistep_monitor_rotation_verify as rotation2_verify
import rust_045_monitor_rotation_journal_verify as journal_verify
import rust_046_monitor_journal_gossip_verify as gossip_verify

OUT = Path("/tmp")
SEEDS = {
    gossip_verify.OBSERVER_1_ID: "0f" * 32,
    gossip_verify.OBSERVER_2_ID: "1f" * 32,
    gossip_verify.OBSERVER_3_ID: "2f" * 32,
}


def signed_report(observer_id: str, target: dict) -> dict:
    statement = {
        "schema": gossip_verify.STATEMENT_SCHEMA,
        "observer_id": observer_id,
        **target,
        "production": False,
    }
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[observer_id]))
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if public != gossip_verify.PINNED_OBSERVERS[observer_id]:
        raise AssertionError("RUST-046 TEST-only journal-observer public-key pin mismatch")
    return {
        "schema": gossip_verify.REPORT_SCHEMA,
        "algorithm": gossip_verify.ALGORITHM,
        "statement": statement,
        "signature": base64.b64encode(private.sign(gossip_verify.observation_message(statement))).decode("ascii"),
    }


def bundle(reports: list[dict]) -> dict:
    reports = sorted(reports, key=lambda report: report["statement"]["observer_id"])
    return {
        "schema": gossip_verify.BUNDLE_SCHEMA,
        "threshold": gossip_verify.THRESHOLD,
        "reports": reports,
        "production": False,
    }


def main() -> None:
    if len(sys.argv) != 2 or len(sys.argv[1]) != 40 or any(c not in "0123456789abcdef" for c in sys.argv[1]):
        raise SystemExit("usage: rust_046_monitor_journal_gossip_fixture.py SOURCE_SHA")
    source_sha = sys.argv[1]

    final_journal_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust045-final-monitor-journal.json", "final monitor journal"
    )
    checkpoint_raw, checkpoint = floor_verify.load_canonical(
        OUT / "axven-rust045-final-monitor-checkpoint.json", "final monitor checkpoint"
    )
    fork_raw, fork_checkpoint = floor_verify.load_canonical(
        OUT / "axven-rust045-observed-fork-monitor-checkpoint.json", "observed fork monitor checkpoint"
    )

    journal_verify.validate_checkpoint_envelope(
        checkpoint, final_journal_raw, rotation2_verify.FINAL_PINNED_MONITORS, "RUST-046 canonical final"
    )
    journal_verify.validate_checkpoint_envelope(
        fork_checkpoint, final_journal_raw, rotation2_verify.FINAL_PINNED_MONITORS, "RUST-046 observed fork"
    )

    target = gossip_verify.canonical_target(checkpoint_raw, checkpoint, source_sha)
    fork_target = gossip_verify.canonical_target(fork_raw, fork_checkpoint, source_sha)
    reports = [signed_report(observer_id, target) for observer_id in sorted(SEEDS)]
    fork_report = signed_report(gossip_verify.OBSERVER_3_ID, fork_target)

    (OUT / "axven-rust046-journal-observer-bundle.json").write_bytes(
        material_verify.canonical(bundle(reports))
    )
    (OUT / "axven-rust046-observed-fork-bundle.json").write_bytes(
        material_verify.canonical(bundle([reports[0], reports[1], fork_report]))
    )
    print("RUST-046 TEST-only monitor-journal observation fixture: GREEN")


if __name__ == "__main__":
    main()
