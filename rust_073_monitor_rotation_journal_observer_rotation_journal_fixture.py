#!/usr/bin/env python3
"""RUST-073 TEST-ONLY observer rotation journal producer."""
from __future__ import annotations

import base64
import copy
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_070_monitor_rotation_journal_observer_verify as observer_verify
import rust_071_monitor_rotation_journal_observer_set_rotation_verify as rotation1_verify
import rust_072_multistep_monitor_rotation_journal_observer_set_rotation_verify as rotation2_verify
import rust_073_monitor_rotation_journal_observer_rotation_journal_verify as journal_verify

OUT = Path("/tmp")
SEEDS = {
    observer_verify.OBSERVER_2_ID: "d9" * 32,
    observer_verify.OBSERVER_3_ID: "e9" * 32,
    rotation1_verify.O4_ID: "f9" * 32,
    rotation2_verify.O5_ID: "09" * 32,
}


def private_for(observer_id: str, pins: dict[str, bytes]) -> Ed25519PrivateKey:
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[observer_id]))
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if public != pins[observer_id]:
        raise AssertionError("RUST-073 TEST-only observer public-key pin mismatch")
    return private


def checkpoint(statement: dict, journal_raw: bytes, pins: dict[str, bytes]) -> dict:
    message = journal_verify.checkpoint_message(statement, journal_raw)
    rows = [
        {
            "observer_id": observer_id,
            "signature": base64.b64encode(
                private_for(observer_id, pins).sign(message)
            ).decode("ascii"),
        }
        for observer_id in sorted(pins)
    ]
    return {
        "schema": journal_verify.CHECKPOINT_SCHEMA,
        "algorithm": journal_verify.ALGORITHM,
        "threshold": journal_verify.THRESHOLD,
        "statement": statement,
        "observers": rows,
        "production": False,
    }


def main() -> None:
    if len(sys.argv) != 2 or len(sys.argv[1]) != 40 or any(
        c not in "0123456789abcdef" for c in sys.argv[1]
    ):
        raise SystemExit(
            "usage: rust_073_monitor_rotation_journal_observer_rotation_journal_fixture.py SOURCE_SHA"
        )
    source_sha = sys.argv[1]

    checkpoint_raw, monitored_checkpoint = floor_verify.load_canonical(
        OUT / "axven-rust069-final-monitor-rotation-checkpoint.json",
        "RUST-069 final monitor rotation checkpoint",
    )
    target = observer_verify.canonical_target(
        checkpoint_raw, monitored_checkpoint, source_sha
    )

    old_bundle_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust070-monitor-rotation-journal-observer-bundle.json",
        "RUST-073 old observer bundle",
    )
    first_rotation_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust071-monitor-rotation-journal-observer-set-rotation.json",
        "RUST-073 first observer rotation",
    )
    first_auth_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust071-monitor-rotation-journal-observer-set-rotation-auth.json",
        "RUST-073 first rotation authorization",
    )
    first_successor_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust071-successor-observer-bundle.json",
        "RUST-073 first successor observer bundle",
    )
    second_rotation_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust072-second-observer-set-rotation.json",
        "RUST-073 second observer rotation",
    )
    second_auth_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust072-second-observer-set-rotation-auth.json",
        "RUST-073 second rotation authorization",
    )
    final_bundle_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust072-final-observer-bundle.json",
        "RUST-073 final observer bundle",
    )

    entries = journal_verify.expected_entries(
        old_bundle_raw, first_rotation_raw, first_auth_raw, first_successor_raw,
        second_rotation_raw, second_auth_raw, final_bundle_raw,
    )
    prefix_journal = journal_verify.expected_journal(entries[:2], source_sha, target)
    prefix_journal_raw = material_verify.canonical(prefix_journal)
    prefix_statement = journal_verify.checkpoint_statement(
        prefix_journal_raw, material_verify.canonical(entries[1]), 1,
        rotation1_verify.new_observer_set(), None, 2, target, source_sha,
    )
    prefix_checkpoint = checkpoint(
        prefix_statement, prefix_journal_raw, rotation1_verify.NEW_PINNED_OBSERVERS
    )
    prefix_checkpoint_raw = material_verify.canonical(prefix_checkpoint)

    final_journal = journal_verify.expected_journal(entries, source_sha, target)
    final_journal_raw = material_verify.canonical(final_journal)
    final_statement = journal_verify.checkpoint_statement(
        final_journal_raw, material_verify.canonical(entries[2]), 2,
        rotation2_verify.final_observer_set(),
        journal_verify.sha256(prefix_checkpoint_raw), 3, target, source_sha,
    )
    final_checkpoint = checkpoint(
        final_statement, final_journal_raw, rotation2_verify.FINAL_PINNED_OBSERVERS
    )

    fork_statement = copy.deepcopy(final_statement)
    fork_statement["observed_target_sha256"] = "0" * 64
    fork_checkpoint = checkpoint(
        fork_statement, final_journal_raw, rotation2_verify.FINAL_PINNED_OBSERVERS
    )

    (OUT / "axven-rust073-prefix-observer-rotation-journal.json").write_bytes(prefix_journal_raw)
    (OUT / "axven-rust073-prefix-observer-rotation-checkpoint.json").write_bytes(
        prefix_checkpoint_raw
    )
    (OUT / "axven-rust073-final-observer-rotation-journal.json").write_bytes(final_journal_raw)
    (OUT / "axven-rust073-final-observer-rotation-checkpoint.json").write_bytes(
        material_verify.canonical(final_checkpoint)
    )
    (OUT / "axven-rust073-observed-fork-observer-rotation-checkpoint.json").write_bytes(
        material_verify.canonical(fork_checkpoint)
    )
    print("RUST-073 TEST-only observer rotation journal fixture: GREEN")


if __name__ == "__main__":
    main()
