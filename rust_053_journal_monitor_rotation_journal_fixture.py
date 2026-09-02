#!/usr/bin/env python3
"""RUST-053 TEST-ONLY journal-monitor rotation journal/checkpoint producer."""
from __future__ import annotations

import base64
import copy
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_050_journal_observer_journal_monitor_verify as monitor_verify
import rust_051_journal_monitor_set_rotation_verify as rotation1_verify
import rust_052_multistep_journal_monitor_rotation_verify as rotation2_verify
import rust_053_journal_monitor_rotation_journal_verify as journal_verify

OUT = Path("/tmp")
SEEDS = {
    monitor_verify.MONITOR_2_ID: "6a" * 32,
    monitor_verify.MONITOR_3_ID: "7a" * 32,
    rotation1_verify.JM4_ID: "8a" * 32,
    rotation2_verify.JM5_ID: "9a" * 32,
}


def private_for(monitor_id: str, pins: dict[str, bytes]) -> Ed25519PrivateKey:
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[monitor_id]))
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if public != pins[monitor_id]:
        raise AssertionError(
            "RUST-053 TEST-only journal-monitor journal public-key pin mismatch"
        )
    return private


def sign_rows(statement: dict, journal_raw: bytes, pins: dict[str, bytes]) -> list[dict]:
    message = journal_verify.checkpoint_message(statement, journal_raw)
    return [
        {
            "monitor_id": monitor_id,
            "signature": base64.b64encode(
                private_for(monitor_id, pins).sign(message)
            ).decode("ascii"),
        }
        for monitor_id in sorted(pins)
    ]


def checkpoint(statement: dict, journal_raw: bytes, pins: dict[str, bytes]) -> dict:
    return {
        "schema": journal_verify.CHECKPOINT_SCHEMA,
        "algorithm": journal_verify.ALGORITHM,
        "threshold": journal_verify.THRESHOLD,
        "statement": statement,
        "monitors": sign_rows(statement, journal_raw, pins),
        "production": False,
    }


def main() -> None:
    if (
        len(sys.argv) != 2
        or len(sys.argv[1]) != 40
        or any(c not in "0123456789abcdef" for c in sys.argv[1])
    ):
        raise SystemExit(
            "usage: rust_053_journal_monitor_rotation_journal_fixture.py SOURCE_SHA"
        )
    source_sha = sys.argv[1]

    checkpoint_raw, checkpoint_value = floor_verify.load_canonical(
        OUT / "axven-rust049-final-journal-observer-checkpoint.json",
        "final journal-observer checkpoint",
    )
    target = monitor_verify.checkpoint_target(
        checkpoint_raw, checkpoint_value["statement"]
    )
    if target["activation_source_commit"] != source_sha:
        raise AssertionError("RUST-053 checkpoint source mismatch")

    old_bundle_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust050-monitor-bundle.json", "old journal-monitor bundle"
    )
    first_rotation_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust051-journal-monitor-set-rotation.json",
        "first journal-monitor rotation",
    )
    first_auth_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust051-journal-monitor-set-rotation-auth.json",
        "first journal-monitor rotation authorization",
    )
    first_successor_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust051-successor-journal-monitor-bundle.json",
        "first journal-monitor successor",
    )
    second_rotation_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust052-second-journal-monitor-set-rotation.json",
        "second journal-monitor rotation",
    )
    second_auth_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust052-second-journal-monitor-set-rotation-auth.json",
        "second journal-monitor rotation authorization",
    )
    final_bundle_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust052-final-journal-monitor-bundle.json",
        "final journal-monitor bundle",
    )

    entries = journal_verify.expected_entries(
        old_bundle_raw,
        first_rotation_raw,
        first_auth_raw,
        first_successor_raw,
        second_rotation_raw,
        second_auth_raw,
        final_bundle_raw,
    )

    prefix_journal = journal_verify.expected_journal(
        entries[:2], source_sha, target
    )
    prefix_journal_raw = material_verify.canonical(prefix_journal)
    prefix_statement = journal_verify.checkpoint_statement(
        prefix_journal_raw,
        material_verify.canonical(entries[1]),
        1,
        rotation1_verify.new_monitor_set(),
        None,
        2,
        target,
        source_sha,
    )
    prefix_checkpoint = checkpoint(
        prefix_statement,
        prefix_journal_raw,
        rotation1_verify.NEW_PINNED_MONITORS,
    )
    prefix_checkpoint_raw = material_verify.canonical(prefix_checkpoint)

    final_journal = journal_verify.expected_journal(entries, source_sha, target)
    final_journal_raw = material_verify.canonical(final_journal)
    final_statement = journal_verify.checkpoint_statement(
        final_journal_raw,
        material_verify.canonical(entries[2]),
        2,
        rotation2_verify.final_monitor_set(),
        hashlib.sha256(prefix_checkpoint_raw).hexdigest(),
        3,
        target,
        source_sha,
    )
    final_checkpoint = checkpoint(
        final_statement,
        final_journal_raw,
        rotation2_verify.FINAL_PINNED_MONITORS,
    )

    fork_statement = copy.deepcopy(final_statement)
    fork_statement["journal_sha256"] = "f" * 64
    fork_statement["head_entry_sha256"] = "e" * 64
    fork_checkpoint = checkpoint(
        fork_statement,
        final_journal_raw,
        rotation2_verify.FINAL_PINNED_MONITORS,
    )

    (OUT / "axven-rust053-prefix-journal-monitor-journal.json").write_bytes(
        prefix_journal_raw
    )
    (OUT / "axven-rust053-prefix-journal-monitor-checkpoint.json").write_bytes(
        prefix_checkpoint_raw
    )
    (OUT / "axven-rust053-final-journal-monitor-journal.json").write_bytes(
        final_journal_raw
    )
    (OUT / "axven-rust053-final-journal-monitor-checkpoint.json").write_bytes(
        material_verify.canonical(final_checkpoint)
    )
    (
        OUT / "axven-rust053-observed-fork-journal-monitor-checkpoint.json"
    ).write_bytes(material_verify.canonical(fork_checkpoint))
    print("RUST-053 TEST-only journal-monitor rotation journal/checkpoint fixture: GREEN")


if __name__ == "__main__":
    main()
