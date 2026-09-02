#!/usr/bin/env python3
"""RUST-045 TEST-only monitor rotation journal/checkpoint producer."""
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
import rust_042_observer_journal_monitor_verify as monitor_verify
import rust_043_monitor_set_rotation_verify as rotation1_verify
import rust_044_multistep_monitor_rotation_verify as rotation2_verify
import rust_045_monitor_rotation_journal_verify as journal_verify

OUT = Path("/tmp")
SEEDS = {
    monitor_verify.MONITOR_2_ID: "bb" * 32,
    monitor_verify.MONITOR_3_ID: "cc" * 32,
    rotation1_verify.M4_ID: "dd" * 32,
    rotation2_verify.M5_ID: "ee" * 32,
}


def private_for(monitor_id: str, pins: dict[str, bytes]) -> Ed25519PrivateKey:
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[monitor_id]))
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if public != pins[monitor_id]:
        raise AssertionError("RUST-045 TEST-only monitor journal public-key pin mismatch")
    return private


def sign_rows(statement: dict, journal_raw: bytes, pins: dict[str, bytes]) -> list[dict]:
    message = journal_verify.checkpoint_message(statement, journal_raw)
    rows = []
    for monitor_id in sorted(pins):
        rows.append({
            "monitor_id": monitor_id,
            "signature": base64.b64encode(private_for(monitor_id, pins).sign(message)).decode("ascii"),
        })
    return rows


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
    if len(sys.argv) != 2 or len(sys.argv[1]) != 40 or any(c not in "0123456789abcdef" for c in sys.argv[1]):
        raise SystemExit("usage: rust_045_monitor_rotation_journal_fixture.py SOURCE_SHA")
    source_sha = sys.argv[1]
    final_observer_checkpoint_raw, final_observer_checkpoint = floor_verify.load_canonical(
        OUT / "axven-rust041-final-observer-checkpoint.json", "final observer checkpoint"
    )
    target = monitor_verify.checkpoint_target(final_observer_checkpoint_raw, final_observer_checkpoint["statement"])
    if target["activation_source_commit"] != source_sha:
        raise AssertionError("RUST-045 observer checkpoint source mismatch")

    old_bundle_raw, _ = floor_verify.load_canonical(OUT / "axven-rust042-monitor-bundle.json", "old monitor bundle")
    first_rotation_raw, _ = floor_verify.load_canonical(OUT / "axven-rust043-monitor-set-rotation.json", "first monitor rotation")
    first_auth_raw, _ = floor_verify.load_canonical(OUT / "axven-rust043-monitor-set-rotation-auth.json", "first monitor auth")
    first_successor_raw, _ = floor_verify.load_canonical(OUT / "axven-rust043-successor-monitor-bundle.json", "first monitor successor")
    second_rotation_raw, _ = floor_verify.load_canonical(OUT / "axven-rust044-second-monitor-set-rotation.json", "second monitor rotation")
    second_auth_raw, _ = floor_verify.load_canonical(OUT / "axven-rust044-second-monitor-set-rotation-auth.json", "second monitor auth")
    final_bundle_raw, _ = floor_verify.load_canonical(OUT / "axven-rust044-final-monitor-bundle.json", "final monitor bundle")
    entries = journal_verify.expected_entries(
        old_bundle_raw, first_rotation_raw, first_auth_raw, first_successor_raw,
        second_rotation_raw, second_auth_raw, final_bundle_raw,
    )
    observer_checkpoint_digest = target["checkpoint_sha256"]
    statement_digest = target["checkpoint_statement_sha256"]

    prefix_journal = journal_verify.expected_journal(
        entries[:2], source_sha, observer_checkpoint_digest, statement_digest,
    )
    prefix_journal_raw = material_verify.canonical(prefix_journal)
    prefix_statement = journal_verify.checkpoint_statement(
        prefix_journal_raw, material_verify.canonical(entries[1]), 1,
        rotation1_verify.new_monitor_set(), None, 2,
        observer_checkpoint_digest, statement_digest, source_sha,
    )
    prefix_checkpoint = checkpoint(prefix_statement, prefix_journal_raw, rotation1_verify.NEW_PINNED_MONITORS)
    prefix_checkpoint_raw = material_verify.canonical(prefix_checkpoint)

    final_journal = journal_verify.expected_journal(
        entries, source_sha, observer_checkpoint_digest, statement_digest,
    )
    final_journal_raw = material_verify.canonical(final_journal)
    final_statement = journal_verify.checkpoint_statement(
        final_journal_raw, material_verify.canonical(entries[2]), 2,
        rotation2_verify.final_monitor_set(), hashlib.sha256(prefix_checkpoint_raw).hexdigest(), 3,
        observer_checkpoint_digest, statement_digest, source_sha,
    )
    final_checkpoint = checkpoint(final_statement, final_journal_raw, rotation2_verify.FINAL_PINNED_MONITORS)

    fork_statement = copy.deepcopy(final_statement)
    fork_statement["journal_sha256"] = "f" * 64
    fork_statement["head_entry_sha256"] = "e" * 64
    fork_checkpoint = checkpoint(fork_statement, final_journal_raw, rotation2_verify.FINAL_PINNED_MONITORS)

    (OUT / "axven-rust045-prefix-monitor-journal.json").write_bytes(prefix_journal_raw)
    (OUT / "axven-rust045-prefix-monitor-checkpoint.json").write_bytes(prefix_checkpoint_raw)
    (OUT / "axven-rust045-final-monitor-journal.json").write_bytes(final_journal_raw)
    (OUT / "axven-rust045-final-monitor-checkpoint.json").write_bytes(material_verify.canonical(final_checkpoint))
    (OUT / "axven-rust045-observed-fork-monitor-checkpoint.json").write_bytes(material_verify.canonical(fork_checkpoint))
    print("RUST-045 TEST-only monitor rotation journal/checkpoint fixture: GREEN")


if __name__ == "__main__":
    main()
