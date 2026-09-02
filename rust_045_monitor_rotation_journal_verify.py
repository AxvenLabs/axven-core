#!/usr/bin/env python3
"""RUST-045: TEST-ONLY append-only monitor-set rotation journal/checkpoint verifier."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_042_observer_journal_monitor_verify as monitor_verify
import rust_043_monitor_set_rotation_verify as rotation1_verify
import rust_044_multistep_monitor_rotation_verify as rotation2_verify

JOURNAL_SCHEMA = "axven-native-observer-journal-monitor-set-rotation-journal-v1"
ENTRY_SCHEMA = "axven-native-observer-journal-monitor-set-rotation-journal-entry-v1"
CHECKPOINT_SCHEMA = "axven-native-observer-journal-monitor-set-rotation-journal-checkpoint-v1"
STATEMENT_SCHEMA = "axven-native-observer-journal-monitor-set-rotation-journal-checkpoint-statement-v1"
CHECKPOINT_DOMAIN = b"AXVEN_NATIVE_OBSERVER_JOURNAL_MONITOR_SET_ROTATION_JOURNAL_CHECKPOINT_V1\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2
JOURNAL_KEYS = frozenset({
    "schema", "activation_source_commit", "observer_checkpoint_sha256",
    "checkpoint_statement_sha256", "entries", "production",
})
ENTRY_KEYS = frozenset({
    "schema", "sequence", "monitor_set_sha256", "rotation_sha256", "rotation_auth_sha256",
    "monitor_bundle_sha256", "cumulative_revoked_monitor_ids", "predecessor_entry_sha256",
})
CHECKPOINT_KEYS = frozenset({"schema", "algorithm", "threshold", "statement", "monitors", "production"})
CHECKPOINT_MONITOR_KEYS = frozenset({"monitor_id", "signature"})
STATEMENT_KEYS = frozenset({
    "schema", "monitor_set_sequence", "monitor_set_sha256", "entry_count", "journal_sha256",
    "head_entry_sha256", "previous_checkpoint_sha256", "observer_checkpoint_sha256",
    "checkpoint_statement_sha256", "activation_source_commit", "production",
})


def canonical(value: dict) -> bytes:
    return material_verify.canonical(value)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def set_sha(monitor_set: dict) -> str:
    return sha256(canonical(monitor_set))


def expected_entries(
    old_bundle_raw: bytes,
    first_rotation_raw: bytes,
    first_auth_raw: bytes,
    first_successor_raw: bytes,
    second_rotation_raw: bytes,
    second_auth_raw: bytes,
    final_bundle_raw: bytes,
) -> list[dict]:
    e0 = {
        "schema": ENTRY_SCHEMA,
        "sequence": 0,
        "monitor_set_sha256": set_sha(rotation1_verify.old_monitor_set()),
        "rotation_sha256": None,
        "rotation_auth_sha256": None,
        "monitor_bundle_sha256": sha256(old_bundle_raw),
        "cumulative_revoked_monitor_ids": [],
        "predecessor_entry_sha256": None,
    }
    e1 = {
        "schema": ENTRY_SCHEMA,
        "sequence": 1,
        "monitor_set_sha256": set_sha(rotation1_verify.new_monitor_set()),
        "rotation_sha256": sha256(first_rotation_raw),
        "rotation_auth_sha256": sha256(first_auth_raw),
        "monitor_bundle_sha256": sha256(first_successor_raw),
        "cumulative_revoked_monitor_ids": [rotation1_verify.REVOKED_MONITOR_ID],
        "predecessor_entry_sha256": sha256(canonical(e0)),
    }
    e2 = {
        "schema": ENTRY_SCHEMA,
        "sequence": 2,
        "monitor_set_sha256": set_sha(rotation2_verify.final_monitor_set()),
        "rotation_sha256": sha256(second_rotation_raw),
        "rotation_auth_sha256": sha256(second_auth_raw),
        "monitor_bundle_sha256": sha256(final_bundle_raw),
        "cumulative_revoked_monitor_ids": rotation2_verify.CUMULATIVE_REVOKED_MONITOR_IDS,
        "predecessor_entry_sha256": sha256(canonical(e1)),
    }
    return [e0, e1, e2]


def expected_journal(
    entries: list[dict],
    source_sha: str,
    observer_checkpoint_sha256: str,
    checkpoint_statement_sha256: str,
) -> dict:
    return {
        "schema": JOURNAL_SCHEMA,
        "activation_source_commit": source_sha,
        "observer_checkpoint_sha256": observer_checkpoint_sha256,
        "checkpoint_statement_sha256": checkpoint_statement_sha256,
        "entries": entries,
        "production": False,
    }


def validate_journal(journal: dict, expected: dict, label: str) -> None:
    if frozenset(journal) != JOURNAL_KEYS or journal.get("schema") != JOURNAL_SCHEMA:
        raise AssertionError(f"invalid {label} monitor journal fields")
    if journal.get("production") is not False:
        raise AssertionError(f"production {label} monitor journal forbidden in RUST-045")
    if journal != expected:
        raise AssertionError(f"{label} monitor journal continuity mismatch")
    entries = journal.get("entries")
    if not isinstance(entries, list) or not entries:
        raise AssertionError(f"empty {label} monitor journal")
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or frozenset(entry) != ENTRY_KEYS or entry.get("schema") != ENTRY_SCHEMA:
            raise AssertionError(f"invalid {label} monitor journal entry")
        if type(entry.get("sequence")) is not int or entry["sequence"] != index:
            raise AssertionError(f"non-monotonic {label} monitor journal sequence")
        if index == 0:
            if entry.get("predecessor_entry_sha256") is not None:
                raise AssertionError(f"unexpected {label} monitor journal genesis predecessor")
        elif entry.get("predecessor_entry_sha256") != sha256(canonical(entries[index - 1])):
            raise AssertionError(f"broken {label} monitor journal hash chain")


def checkpoint_statement(
    journal_raw: bytes,
    head_entry_raw: bytes,
    monitor_set_sequence: int,
    monitor_set: dict,
    previous_checkpoint_sha256: str | None,
    entry_count: int,
    observer_checkpoint_sha256: str,
    checkpoint_statement_sha256: str,
    source_sha: str,
) -> dict:
    return {
        "schema": STATEMENT_SCHEMA,
        "monitor_set_sequence": monitor_set_sequence,
        "monitor_set_sha256": set_sha(monitor_set),
        "entry_count": entry_count,
        "journal_sha256": sha256(journal_raw),
        "head_entry_sha256": sha256(head_entry_raw),
        "previous_checkpoint_sha256": previous_checkpoint_sha256,
        "observer_checkpoint_sha256": observer_checkpoint_sha256,
        "checkpoint_statement_sha256": checkpoint_statement_sha256,
        "activation_source_commit": source_sha,
        "production": False,
    }


def checkpoint_message(statement: dict, journal_raw: bytes) -> bytes:
    statement_raw = canonical(statement)
    return (
        CHECKPOINT_DOMAIN
        + len(statement_raw).to_bytes(8, "big") + statement_raw
        + len(journal_raw).to_bytes(8, "big") + journal_raw
    )


def validate_checkpoint_envelope(
    checkpoint: dict,
    journal_raw: bytes,
    pins: dict[str, bytes],
    label: str,
) -> dict:
    if frozenset(checkpoint) != CHECKPOINT_KEYS or checkpoint.get("schema") != CHECKPOINT_SCHEMA:
        raise AssertionError(f"invalid {label} monitor checkpoint fields")
    if checkpoint.get("algorithm") != ALGORITHM or checkpoint.get("production") is not False:
        raise AssertionError(f"invalid {label} monitor checkpoint boundary")
    if type(checkpoint.get("threshold")) is not int or checkpoint["threshold"] != THRESHOLD:
        raise AssertionError(f"invalid {label} monitor checkpoint threshold")
    statement = checkpoint.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != STATEMENT_KEYS:
        raise AssertionError(f"invalid {label} monitor checkpoint statement fields")
    if statement.get("schema") != STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError(f"invalid {label} monitor checkpoint statement boundary")
    monitors = checkpoint.get("monitors")
    if not isinstance(monitors, list) or not (THRESHOLD <= len(monitors) <= len(pins)):
        raise AssertionError(f"invalid {label} monitor checkpoint signature count")
    if not all(isinstance(item, dict) and frozenset(item) == CHECKPOINT_MONITOR_KEYS for item in monitors):
        raise AssertionError(f"invalid {label} monitor checkpoint signature row")
    ids = [item["monitor_id"] for item in monitors]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError(f"{label} monitor checkpoint ids must be unique and sorted")
    if any(monitor_id not in pins for monitor_id in ids):
        raise AssertionError(f"unknown {label} monitor checkpoint signer")
    message = checkpoint_message(statement, journal_raw)
    for item in monitors:
        material_verify.ed25519_verify(
            pins[item["monitor_id"]],
            material_verify.decode_signature(item["signature"]),
            message,
        )
    return statement


def validate_checkpoint(
    checkpoint: dict,
    journal_raw: bytes,
    expected_statement: dict,
    pins: dict[str, bytes],
    label: str,
) -> None:
    statement = validate_checkpoint_envelope(checkpoint, journal_raw, pins, label)
    if statement != expected_statement:
        raise AssertionError(f"{label} monitor checkpoint statement mismatch")


def reject_observed_fork(
    canonical_checkpoint_raw: bytes,
    canonical_checkpoint: dict,
    observed_checkpoint_raw: bytes,
    observed_checkpoint: dict,
    journal_raw: bytes,
    pins: dict[str, bytes],
) -> None:
    left = validate_checkpoint_envelope(canonical_checkpoint, journal_raw, pins, "canonical final")
    right = validate_checkpoint_envelope(observed_checkpoint, journal_raw, pins, "observed final")
    same_parent = (
        left.get("monitor_set_sequence") == right.get("monitor_set_sequence")
        and left.get("previous_checkpoint_sha256") == right.get("previous_checkpoint_sha256")
    )
    if same_parent and canonical_checkpoint_raw != observed_checkpoint_raw:
        raise AssertionError("observed same-parent monitor-rotation-journal checkpoint fork")


def verify(
    final_state_path: Path,
    external_floor_path: Path,
    first_witness_rotation_path: Path,
    first_witness_auth_path: Path,
    first_witness_quorum_path: Path,
    second_witness_rotation_path: Path,
    second_witness_auth_path: Path,
    final_witness_quorum_path: Path,
    prefix_witness_journal_path: Path,
    prefix_witness_checkpoint_path: Path,
    final_witness_journal_path: Path,
    final_witness_checkpoint_path: Path,
    old_observer_bundle_path: Path,
    first_observer_rotation_path: Path,
    first_observer_auth_path: Path,
    first_observer_successor_path: Path,
    second_observer_rotation_path: Path,
    second_observer_auth_path: Path,
    final_observer_bundle_path: Path,
    prefix_observer_journal_path: Path,
    prefix_observer_checkpoint_path: Path,
    final_observer_journal_path: Path,
    final_observer_checkpoint_path: Path,
    old_monitor_bundle_path: Path,
    first_monitor_rotation_path: Path,
    first_monitor_auth_path: Path,
    first_monitor_successor_path: Path,
    second_monitor_rotation_path: Path,
    second_monitor_auth_path: Path,
    final_monitor_bundle_path: Path,
    prefix_monitor_journal_path: Path,
    prefix_monitor_checkpoint_path: Path,
    final_monitor_journal_path: Path,
    final_monitor_checkpoint_path: Path,
    expected_source_sha: str,
    required_floor_text: str,
) -> None:
    rotation2_verify.verify(
        final_state_path, external_floor_path, first_witness_rotation_path, first_witness_auth_path,
        first_witness_quorum_path, second_witness_rotation_path, second_witness_auth_path,
        final_witness_quorum_path, prefix_witness_journal_path, prefix_witness_checkpoint_path,
        final_witness_journal_path, final_witness_checkpoint_path, old_observer_bundle_path,
        first_observer_rotation_path, first_observer_auth_path, first_observer_successor_path,
        second_observer_rotation_path, second_observer_auth_path, final_observer_bundle_path,
        prefix_observer_journal_path, prefix_observer_checkpoint_path, final_observer_journal_path,
        final_observer_checkpoint_path, old_monitor_bundle_path, first_monitor_rotation_path,
        first_monitor_auth_path, first_monitor_successor_path, second_monitor_rotation_path,
        second_monitor_auth_path, final_monitor_bundle_path, expected_source_sha, required_floor_text,
    )
    final_observer_checkpoint_raw, final_observer_checkpoint = floor_verify.load_canonical(
        final_observer_checkpoint_path, "final observer checkpoint"
    )
    target = monitor_verify.checkpoint_target(final_observer_checkpoint_raw, final_observer_checkpoint["statement"])
    old_bundle_raw, _ = floor_verify.load_canonical(old_monitor_bundle_path, "old monitor bundle")
    first_rotation_raw, _ = floor_verify.load_canonical(first_monitor_rotation_path, "first monitor rotation")
    first_auth_raw, _ = floor_verify.load_canonical(first_monitor_auth_path, "first monitor auth")
    first_successor_raw, _ = floor_verify.load_canonical(first_monitor_successor_path, "first monitor successor")
    second_rotation_raw, _ = floor_verify.load_canonical(second_monitor_rotation_path, "second monitor rotation")
    second_auth_raw, _ = floor_verify.load_canonical(second_monitor_auth_path, "second monitor auth")
    final_bundle_raw, _ = floor_verify.load_canonical(final_monitor_bundle_path, "final monitor bundle")
    entries = expected_entries(
        old_bundle_raw, first_rotation_raw, first_auth_raw, first_successor_raw,
        second_rotation_raw, second_auth_raw, final_bundle_raw,
    )
    prefix_journal_raw, prefix_journal = floor_verify.load_canonical(prefix_monitor_journal_path, "prefix monitor journal")
    prefix_checkpoint_raw, prefix_checkpoint = floor_verify.load_canonical(prefix_monitor_checkpoint_path, "prefix monitor checkpoint")
    final_journal_raw, final_journal = floor_verify.load_canonical(final_monitor_journal_path, "final monitor journal")
    _, final_checkpoint = floor_verify.load_canonical(final_monitor_checkpoint_path, "final monitor checkpoint")

    observer_checkpoint_digest = target["checkpoint_sha256"]
    statement_digest = target["checkpoint_statement_sha256"]
    validate_journal(
        prefix_journal,
        expected_journal(entries[:2], expected_source_sha, observer_checkpoint_digest, statement_digest),
        "prefix",
    )
    prefix_statement = checkpoint_statement(
        prefix_journal_raw, canonical(entries[1]), 1, rotation1_verify.new_monitor_set(), None, 2,
        observer_checkpoint_digest, statement_digest, expected_source_sha,
    )
    validate_checkpoint(
        prefix_checkpoint, prefix_journal_raw, prefix_statement,
        rotation1_verify.NEW_PINNED_MONITORS, "prefix",
    )

    validate_journal(
        final_journal,
        expected_journal(entries, expected_source_sha, observer_checkpoint_digest, statement_digest),
        "final",
    )
    if final_journal["entries"][:2] != prefix_journal["entries"]:
        raise AssertionError("final monitor journal rewrites checkpointed prefix")
    final_statement = checkpoint_statement(
        final_journal_raw, canonical(entries[2]), 2, rotation2_verify.final_monitor_set(),
        sha256(prefix_checkpoint_raw), 3, observer_checkpoint_digest, statement_digest, expected_source_sha,
    )
    validate_checkpoint(
        final_checkpoint, final_journal_raw, final_statement,
        rotation2_verify.FINAL_PINNED_MONITORS, "final",
    )
    print(
        "RUST-045 append-only monitor rotation journal: GREEN "
        f"source={expected_source_sha} entries=3 checkpoint={sha256(canonical(final_checkpoint))}"
    )


def main() -> None:
    if len(sys.argv) != 38 or sys.argv[1] != "verify":
        raise SystemExit("usage: rust_045_monitor_rotation_journal_verify.py verify ... PREFIX_MON_JOURNAL PREFIX_MON_CHECKPOINT FINAL_MON_JOURNAL FINAL_MON_CHECKPOINT SOURCE_SHA REQUIRED_FLOOR")
    paths = [Path(value) for value in sys.argv[2:-2]]
    verify(*paths, sys.argv[-2], sys.argv[-1])


if __name__ == "__main__":
    main()
