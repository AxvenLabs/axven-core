#!/usr/bin/env python3
"""RUST-065 TEST-ONLY monitor-rotation-journal observer rotation journal/checkpoint producer."""
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
import rust_062_observer_rotation_journal_monitor_rotation_journal_gossip_verify as gossip_verify
import rust_063_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify as rotation1_verify
import rust_064_multistep_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify as rotation2_verify
import rust_065_monitor_rotation_journal_observer_rotation_journal_verify as journal_verify

OUT = Path("/tmp")
SEEDS = {
    gossip_verify.OBSERVER_2_ID: "39" * 32,
    gossip_verify.OBSERVER_3_ID: "49" * 32,
    rotation1_verify.O4_ID: "59" * 32,
    rotation2_verify.O5_ID: "69" * 32,
}


def private_for(observer_id: str, pins: dict[str, bytes]) -> Ed25519PrivateKey:
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[observer_id]))
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if public != pins[observer_id]:
        raise AssertionError(
            "RUST-065 TEST-only monitor-rotation-journal observer journal public-key pin mismatch"
        )
    return private


def sign_rows(statement: dict, journal_raw: bytes, pins: dict[str, bytes]) -> list[dict]:
    message = journal_verify.checkpoint_message(statement, journal_raw)
    return [
        {
            "observer_id": observer_id,
            "signature": base64.b64encode(
                private_for(observer_id, pins).sign(message)
            ).decode("ascii"),
        }
        for observer_id in sorted(pins)
    ]


def checkpoint(statement: dict, journal_raw: bytes, pins: dict[str, bytes]) -> dict:
    return {
        "schema": journal_verify.CHECKPOINT_SCHEMA,
        "algorithm": journal_verify.ALGORITHM,
        "threshold": journal_verify.THRESHOLD,
        "statement": statement,
        "observers": sign_rows(statement, journal_raw, pins),
        "production": False,
    }


def main() -> None:
    if (
        len(sys.argv) != 2
        or len(sys.argv[1]) != 40
        or any(c not in "0123456789abcdef" for c in sys.argv[1])
    ):
        raise SystemExit(
            "usage: rust_065_monitor_rotation_journal_observer_rotation_journal_fixture.py SOURCE_SHA"
        )
    source_sha = sys.argv[1]

    monitored_checkpoint_raw, monitored_checkpoint = floor_verify.load_canonical(
        OUT / "axven-rust061-final-monitor-rotation-checkpoint.json",
        "final observer-rotation-journal monitor rotation checkpoint",
    )
    target = gossip_verify.canonical_target(
        monitored_checkpoint_raw, monitored_checkpoint, source_sha
    )

    old_bundle_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust062-monitor-rotation-journal-observer-bundle.json",
        "old monitor-rotation-journal observer bundle",
    )
    first_rotation_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust063-monitor-rotation-journal-observer-set-rotation.json",
        "first monitor-rotation-journal observer rotation",
    )
    first_auth_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust063-monitor-rotation-journal-observer-set-rotation-auth.json",
        "first monitor-rotation-journal observer rotation authorization",
    )
    first_successor_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust063-successor-observer-bundle.json",
        "first successor monitor-rotation-journal observer bundle",
    )
    second_rotation_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust064-second-monitor-rotation-journal-observer-set-rotation.json",
        "second monitor-rotation-journal observer rotation",
    )
    second_auth_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust064-second-monitor-rotation-journal-observer-set-rotation-auth.json",
        "second monitor-rotation-journal observer rotation authorization",
    )
    final_bundle_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust064-final-observer-bundle.json",
        "final monitor-rotation-journal observer bundle",
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

    prefix_journal = journal_verify.expected_journal(entries[:2], source_sha, target)
    prefix_journal_raw = material_verify.canonical(prefix_journal)
    prefix_statement = journal_verify.checkpoint_statement(
        prefix_journal_raw,
        material_verify.canonical(entries[1]),
        1,
        rotation1_verify.new_observer_set(),
        None,
        2,
        target,
        source_sha,
    )
    prefix_checkpoint = checkpoint(
        prefix_statement, prefix_journal_raw, rotation1_verify.NEW_PINNED_OBSERVERS
    )
    prefix_checkpoint_raw = material_verify.canonical(prefix_checkpoint)

    final_journal = journal_verify.expected_journal(entries, source_sha, target)
    final_journal_raw = material_verify.canonical(final_journal)
    final_statement = journal_verify.checkpoint_statement(
        final_journal_raw,
        material_verify.canonical(entries[2]),
        2,
        rotation2_verify.final_observer_set(),
        hashlib.sha256(prefix_checkpoint_raw).hexdigest(),
        3,
        target,
        source_sha,
    )
    final_checkpoint = checkpoint(
        final_statement, final_journal_raw, rotation2_verify.FINAL_PINNED_OBSERVERS
    )

    fork_statement = copy.deepcopy(final_statement)
    fork_statement["journal_sha256"] = "f" * 64
    fork_statement["head_entry_sha256"] = "e" * 64
    fork_checkpoint = checkpoint(
        fork_statement, final_journal_raw, rotation2_verify.FINAL_PINNED_OBSERVERS
    )

    (
        OUT / "axven-rust065-prefix-monitor-rotation-journal-observer-rotation-journal.json"
    ).write_bytes(prefix_journal_raw)
    (
        OUT / "axven-rust065-prefix-monitor-rotation-journal-observer-rotation-checkpoint.json"
    ).write_bytes(prefix_checkpoint_raw)
    (
        OUT / "axven-rust065-final-monitor-rotation-journal-observer-rotation-journal.json"
    ).write_bytes(final_journal_raw)
    (
        OUT / "axven-rust065-final-monitor-rotation-journal-observer-rotation-checkpoint.json"
    ).write_bytes(material_verify.canonical(final_checkpoint))
    (
        OUT / "axven-rust065-observed-fork-monitor-rotation-journal-observer-rotation-checkpoint.json"
    ).write_bytes(material_verify.canonical(fork_checkpoint))
    print(
        "RUST-065 TEST-only monitor-rotation-journal observer rotation journal/checkpoint fixture: GREEN"
    )


if __name__ == "__main__":
    main()
