#!/usr/bin/env python3
"""RUST-049: TEST-ONLY append-only journal-observer rotation journal/checkpoint verifier."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_046_monitor_journal_gossip_verify as gossip_verify
import rust_047_journal_observer_set_rotation_verify as rotation1_verify
import rust_048_multistep_journal_observer_rotation_verify as rotation2_verify

JOURNAL_SCHEMA = "axven-native-monitor-journal-observer-set-rotation-journal-v1"
ENTRY_SCHEMA = "axven-native-monitor-journal-observer-set-rotation-journal-entry-v1"
CHECKPOINT_SCHEMA = "axven-native-monitor-journal-observer-set-rotation-journal-checkpoint-v1"
STATEMENT_SCHEMA = "axven-native-monitor-journal-observer-set-rotation-journal-checkpoint-statement-v1"
CHECKPOINT_DOMAIN = b"AXVEN_NATIVE_MONITOR_JOURNAL_OBSERVER_SET_ROTATION_JOURNAL_CHECKPOINT_V1\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2
JOURNAL_KEYS = frozenset({
    "schema", "activation_source_commit", "checkpoint_sha256",
    "checkpoint_statement_sha256", "entries", "production",
})
ENTRY_KEYS = frozenset({
    "schema", "sequence", "observer_set_sha256", "rotation_sha256", "rotation_auth_sha256",
    "observer_bundle_sha256", "cumulative_revoked_observer_ids", "predecessor_entry_sha256",
})
CHECKPOINT_KEYS = frozenset({"schema", "algorithm", "threshold", "statement", "observers", "production"})
CHECKPOINT_OBSERVER_KEYS = frozenset({"observer_id", "signature"})
STATEMENT_KEYS = frozenset({
    "schema", "observer_set_sequence", "observer_set_sha256", "entry_count", "journal_sha256",
    "head_entry_sha256", "previous_checkpoint_sha256", "checkpoint_sha256",
    "checkpoint_statement_sha256", "activation_source_commit", "production",
})


def canonical(value: dict) -> bytes:
    return material_verify.canonical(value)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def set_sha(observer_set: dict) -> str:
    return sha256(canonical(observer_set))


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
        "observer_set_sha256": set_sha(rotation1_verify.old_observer_set()),
        "rotation_sha256": None,
        "rotation_auth_sha256": None,
        "observer_bundle_sha256": sha256(old_bundle_raw),
        "cumulative_revoked_observer_ids": [],
        "predecessor_entry_sha256": None,
    }
    e1 = {
        "schema": ENTRY_SCHEMA,
        "sequence": 1,
        "observer_set_sha256": set_sha(rotation1_verify.new_observer_set()),
        "rotation_sha256": sha256(first_rotation_raw),
        "rotation_auth_sha256": sha256(first_auth_raw),
        "observer_bundle_sha256": sha256(first_successor_raw),
        "cumulative_revoked_observer_ids": [rotation1_verify.REVOKED_OBSERVER_ID],
        "predecessor_entry_sha256": sha256(canonical(e0)),
    }
    e2 = {
        "schema": ENTRY_SCHEMA,
        "sequence": 2,
        "observer_set_sha256": set_sha(rotation2_verify.final_observer_set()),
        "rotation_sha256": sha256(second_rotation_raw),
        "rotation_auth_sha256": sha256(second_auth_raw),
        "observer_bundle_sha256": sha256(final_bundle_raw),
        "cumulative_revoked_observer_ids": rotation2_verify.CUMULATIVE_REVOKED_OBSERVER_IDS,
        "predecessor_entry_sha256": sha256(canonical(e1)),
    }
    return [e0, e1, e2]


def expected_journal(
    entries: list[dict],
    source_sha: str,
    checkpoint_sha256: str,
    checkpoint_statement_sha256: str,
) -> dict:
    return {
        "schema": JOURNAL_SCHEMA,
        "activation_source_commit": source_sha,
        "checkpoint_sha256": checkpoint_sha256,
        "checkpoint_statement_sha256": checkpoint_statement_sha256,
        "entries": entries,
        "production": False,
    }


def validate_journal(journal: dict, expected: dict, label: str) -> None:
    if frozenset(journal) != JOURNAL_KEYS or journal.get("schema") != JOURNAL_SCHEMA:
        raise AssertionError(f"invalid {label} journal-observer journal fields")
    if journal.get("production") is not False:
        raise AssertionError(f"production {label} journal-observer journal forbidden in RUST-049")
    if journal != expected:
        raise AssertionError(f"{label} journal-observer journal continuity mismatch")
    entries = journal.get("entries")
    if not isinstance(entries, list) or not entries:
        raise AssertionError(f"empty {label} journal-observer journal")
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or frozenset(entry) != ENTRY_KEYS or entry.get("schema") != ENTRY_SCHEMA:
            raise AssertionError(f"invalid {label} journal-observer journal entry")
        if type(entry.get("sequence")) is not int or entry["sequence"] != index:
            raise AssertionError(f"non-monotonic {label} journal-observer journal sequence")
        if index == 0:
            if entry.get("predecessor_entry_sha256") is not None:
                raise AssertionError(f"unexpected {label} journal-observer journal genesis predecessor")
        elif entry.get("predecessor_entry_sha256") != sha256(canonical(entries[index - 1])):
            raise AssertionError(f"broken {label} journal-observer journal hash chain")


def checkpoint_statement(
    journal_raw: bytes,
    head_entry_raw: bytes,
    observer_set_sequence: int,
    observer_set: dict,
    previous_checkpoint_sha256: str | None,
    entry_count: int,
    checkpoint_sha256: str,
    checkpoint_statement_sha256: str,
    source_sha: str,
) -> dict:
    return {
        "schema": STATEMENT_SCHEMA,
        "observer_set_sequence": observer_set_sequence,
        "observer_set_sha256": set_sha(observer_set),
        "entry_count": entry_count,
        "journal_sha256": sha256(journal_raw),
        "head_entry_sha256": sha256(head_entry_raw),
        "previous_checkpoint_sha256": previous_checkpoint_sha256,
        "checkpoint_sha256": checkpoint_sha256,
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
        raise AssertionError(f"invalid {label} journal-observer checkpoint fields")
    if checkpoint.get("algorithm") != ALGORITHM or checkpoint.get("production") is not False:
        raise AssertionError(f"invalid {label} journal-observer checkpoint boundary")
    if type(checkpoint.get("threshold")) is not int or checkpoint["threshold"] != THRESHOLD:
        raise AssertionError(f"invalid {label} journal-observer checkpoint threshold")
    statement = checkpoint.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != STATEMENT_KEYS:
        raise AssertionError(f"invalid {label} journal-observer checkpoint statement fields")
    if statement.get("schema") != STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError(f"invalid {label} journal-observer checkpoint statement boundary")
    observers = checkpoint.get("observers")
    if not isinstance(observers, list) or not (THRESHOLD <= len(observers) <= len(pins)):
        raise AssertionError(f"invalid {label} journal-observer checkpoint signature count")
    if not all(isinstance(item, dict) and frozenset(item) == CHECKPOINT_OBSERVER_KEYS for item in observers):
        raise AssertionError(f"invalid {label} journal-observer checkpoint signature row")
    ids = [item["observer_id"] for item in observers]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError(f"{label} journal-observer checkpoint ids must be unique and sorted")
    if any(observer_id not in pins for observer_id in ids):
        raise AssertionError(f"unknown {label} journal-observer checkpoint signer")
    message = checkpoint_message(statement, journal_raw)
    for item in observers:
        material_verify.ed25519_verify(
            pins[item["observer_id"]],
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
        raise AssertionError(f"{label} journal-observer checkpoint statement mismatch")


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
        left.get("observer_set_sequence") == right.get("observer_set_sequence")
        and left.get("previous_checkpoint_sha256") == right.get("previous_checkpoint_sha256")
    )
    if same_parent and canonical_checkpoint_raw != observed_checkpoint_raw:
        raise AssertionError("observed same-parent journal-observer-rotation-journal checkpoint fork")


def verify(*args) -> None:
    if len(args) != 47:
        raise AssertionError("unexpected RUST-049 verifier argument count")
    *path_args, expected_source_sha, required_floor_text = args
    if len(path_args) != 45:
        raise AssertionError("unexpected RUST-049 path count")

    base_paths = path_args[:34]
    (
        old_bundle_path,
        first_rotation_path,
        first_auth_path,
        first_successor_path,
        second_rotation_path,
        second_auth_path,
        final_bundle_path,
    ) = path_args[34:41]
    (
        prefix_journal_path,
        prefix_checkpoint_path,
        final_journal_path,
        final_checkpoint_path,
    ) = path_args[41:45]

    rotation2_verify.verify(
        *base_paths,
        old_bundle_path, first_rotation_path, first_auth_path, first_successor_path,
        second_rotation_path, second_auth_path, final_bundle_path,
        expected_source_sha, required_floor_text,
    )

    checkpoint_raw, checkpoint = floor_verify.load_canonical(base_paths[-1], "final monitor checkpoint")
    target = gossip_verify.canonical_target(checkpoint_raw, checkpoint, expected_source_sha)

    old_bundle_raw, _ = floor_verify.load_canonical(old_bundle_path, "old journal-observer bundle")
    first_rotation_raw, _ = floor_verify.load_canonical(first_rotation_path, "first journal-observer rotation")
    first_auth_raw, _ = floor_verify.load_canonical(first_auth_path, "first journal-observer auth")
    first_successor_raw, _ = floor_verify.load_canonical(first_successor_path, "first journal-observer successor")
    second_rotation_raw, _ = floor_verify.load_canonical(second_rotation_path, "second journal-observer rotation")
    second_auth_raw, _ = floor_verify.load_canonical(second_auth_path, "second journal-observer auth")
    final_bundle_raw, _ = floor_verify.load_canonical(final_bundle_path, "final journal-observer bundle")
    entries = expected_entries(
        old_bundle_raw, first_rotation_raw, first_auth_raw, first_successor_raw,
        second_rotation_raw, second_auth_raw, final_bundle_raw,
    )

    prefix_journal_raw, prefix_journal = floor_verify.load_canonical(prefix_journal_path, "prefix journal-observer journal")
    prefix_checkpoint_raw, prefix_checkpoint = floor_verify.load_canonical(prefix_checkpoint_path, "prefix journal-observer checkpoint")
    final_journal_raw, final_journal = floor_verify.load_canonical(final_journal_path, "final journal-observer journal")
    _, final_checkpoint = floor_verify.load_canonical(final_checkpoint_path, "final journal-observer checkpoint")

    checkpoint_digest = target["checkpoint_sha256"]
    statement_digest = target["checkpoint_statement_sha256"]

    validate_journal(
        prefix_journal,
        expected_journal(entries[:2], expected_source_sha, checkpoint_digest, statement_digest),
        "prefix",
    )
    prefix_statement = checkpoint_statement(
        prefix_journal_raw, canonical(entries[1]), 1, rotation1_verify.new_observer_set(), None, 2,
        checkpoint_digest, statement_digest, expected_source_sha,
    )
    validate_checkpoint(
        prefix_checkpoint, prefix_journal_raw, prefix_statement,
        rotation1_verify.NEW_PINNED_OBSERVERS, "prefix",
    )

    validate_journal(
        final_journal,
        expected_journal(entries, expected_source_sha, checkpoint_digest, statement_digest),
        "final",
    )
    if final_journal["entries"][:2] != prefix_journal["entries"]:
        raise AssertionError("final journal-observer journal rewrites checkpointed prefix")
    final_statement = checkpoint_statement(
        final_journal_raw, canonical(entries[2]), 2, rotation2_verify.final_observer_set(),
        sha256(prefix_checkpoint_raw), 3, checkpoint_digest, statement_digest, expected_source_sha,
    )
    validate_checkpoint(
        final_checkpoint, final_journal_raw, final_statement,
        rotation2_verify.FINAL_PINNED_OBSERVERS, "final",
    )
    print(
        "RUST-049 append-only journal-observer rotation journal: GREEN "
        f"source={expected_source_sha} entries=3 checkpoint={sha256(canonical(final_checkpoint))}"
    )


def main() -> None:
    if len(sys.argv) != 49 or sys.argv[1] != "verify":
        raise SystemExit(
            "usage: rust_049_journal_observer_rotation_journal_verify.py verify "
            "... PREFIX_JOURNAL PREFIX_CHECKPOINT FINAL_JOURNAL FINAL_CHECKPOINT SOURCE_SHA REQUIRED_FLOOR"
        )
    paths = [Path(value) for value in sys.argv[2:-2]]
    verify(*paths, sys.argv[-2], sys.argv[-1])


if __name__ == "__main__":
    main()
