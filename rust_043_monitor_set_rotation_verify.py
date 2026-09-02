#!/usr/bin/env python3
"""RUST-043: TEST-ONLY checkpoint-monitor set rotation/revocation continuity."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_041_observer_rotation_journal_verify as journal_verify
import rust_042_observer_journal_monitor_verify as monitor_verify

MONITOR_SET_SCHEMA = "axven-native-observer-journal-monitor-set-v1"
ROTATION_SCHEMA = "axven-native-observer-journal-monitor-set-rotation-v1"
ROTATION_AUTH_SCHEMA = "axven-native-observer-journal-monitor-set-rotation-quorum-v1"
ROTATION_PAYLOAD_TYPE = "application/vnd.axven.native-observer-journal-monitor-set-rotation.v1+json"
SUCCESSOR_BUNDLE_SCHEMA = "axven-native-observer-journal-checkpoint-monitor-bundle-v2"
SUCCESSOR_REPORT_SCHEMA = "axven-native-observer-journal-checkpoint-monitor-report-v2"
SUCCESSOR_STATEMENT_SCHEMA = "axven-native-observer-journal-checkpoint-monitor-statement-v2"
ROTATION_DOMAIN = b"AXVEN_NATIVE_OBSERVER_JOURNAL_MONITOR_SET_ROTATION_V1\x00"
SUCCESSOR_DOMAIN = b"AXVEN_NATIVE_OBSERVER_JOURNAL_CHECKPOINT_MONITOR_V2\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2
OLD_SET_SEQUENCE = 0
NEW_SET_SEQUENCE = 1
M4_ID = "rust-043-test-only-monitor-4-v1"
M4_PUBLIC_KEY = bytes.fromhex("68460ebef3b138164ec7fd8610e95800df7598f70f2f2ea7db5172ac74ebc144")
REVOKED_MONITOR_ID = monitor_verify.MONITOR_1_ID
OLD_PINNED_MONITORS = dict(monitor_verify.PINNED_MONITORS)
NEW_PINNED_MONITORS = {
    monitor_verify.MONITOR_2_ID: monitor_verify.MONITOR_2_PUBLIC_KEY,
    monitor_verify.MONITOR_3_ID: monitor_verify.MONITOR_3_PUBLIC_KEY,
    M4_ID: M4_PUBLIC_KEY,
}
SET_KEYS = frozenset({"schema", "sequence", "threshold", "monitors", "production"})
SET_MONITOR_KEYS = frozenset({"monitor_id", "public_key"})
ROTATION_KEYS = frozenset({
    "schema", "sequence", "from_set_sha256", "to_set", "revoked_monitor_ids",
    "predecessor_monitor_bundle_sha256", "checkpoint_sha256", "activation_source_commit", "production",
})
AUTH_KEYS = frozenset({"schema", "algorithm", "threshold", "payload_type", "payload_sha256", "monitors", "production"})
AUTH_MONITOR_KEYS = frozenset({"monitor_id", "signature"})
BUNDLE_KEYS = frozenset({"schema", "monitor_set_sequence", "monitor_set_sha256", "threshold", "reports", "production"})
REPORT_KEYS = frozenset({"schema", "algorithm", "statement", "signature"})
STATEMENT_KEYS = frozenset({
    "schema", "monitor_id", "monitor_set_sequence", "monitor_set_sha256",
    "checkpoint_sha256", "observer_set_sequence", "observer_set_sha256", "journal_sha256",
    "head_entry_sha256", "previous_checkpoint_sha256", "checkpoint_statement_sha256",
    "activation_source_commit", "production",
})
TARGET_KEYS = frozenset(monitor_verify.TARGET_KEYS)


def canonical(value: dict) -> bytes:
    return material_verify.canonical(value)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def monitor_set(sequence: int, pins: dict[str, bytes]) -> dict:
    return {
        "schema": MONITOR_SET_SCHEMA,
        "sequence": sequence,
        "threshold": THRESHOLD,
        "monitors": [
            {"monitor_id": monitor_id, "public_key": pins[monitor_id].hex()}
            for monitor_id in sorted(pins)
        ],
        "production": False,
    }


def old_monitor_set() -> dict:
    return monitor_set(OLD_SET_SEQUENCE, OLD_PINNED_MONITORS)


def new_monitor_set() -> dict:
    return monitor_set(NEW_SET_SEQUENCE, NEW_PINNED_MONITORS)


def rotation_message(raw: bytes) -> bytes:
    return ROTATION_DOMAIN + len(raw).to_bytes(8, "big") + raw


def successor_message(statement: dict) -> bytes:
    raw = canonical(statement)
    return SUCCESSOR_DOMAIN + len(raw).to_bytes(8, "big") + raw


def validate_rotation(rotation: dict, target: dict, old_bundle_raw: bytes, source_sha: str) -> None:
    if frozenset(rotation) != ROTATION_KEYS or rotation.get("schema") != ROTATION_SCHEMA:
        raise AssertionError("invalid monitor-set rotation fields")
    if type(rotation.get("sequence")) is not int or rotation["sequence"] != NEW_SET_SEQUENCE:
        raise AssertionError("invalid monitor-set rotation sequence")
    if rotation.get("from_set_sha256") != sha256(canonical(old_monitor_set())):
        raise AssertionError("monitor-set predecessor mismatch")
    if rotation.get("to_set") != new_monitor_set():
        raise AssertionError("unexpected successor monitor set")
    if rotation.get("revoked_monitor_ids") != [REVOKED_MONITOR_ID]:
        raise AssertionError("monitor revocation continuity mismatch")
    if rotation.get("predecessor_monitor_bundle_sha256") != sha256(old_bundle_raw):
        raise AssertionError("predecessor monitor bundle digest mismatch")
    if rotation.get("checkpoint_sha256") != target["checkpoint_sha256"]:
        raise AssertionError("monitor rotation checkpoint binding mismatch")
    if rotation.get("activation_source_commit") != source_sha:
        raise AssertionError("monitor rotation source mismatch")
    if rotation.get("production") is not False:
        raise AssertionError("production monitor-set rotation forbidden in RUST-043")


def validate_rotation_auth(auth: dict, rotation_raw: bytes) -> None:
    if frozenset(auth) != AUTH_KEYS or auth.get("schema") != ROTATION_AUTH_SCHEMA:
        raise AssertionError("invalid monitor-set rotation authorization fields")
    if auth.get("algorithm") != ALGORITHM or auth.get("payload_type") != ROTATION_PAYLOAD_TYPE:
        raise AssertionError("invalid monitor-set rotation authorization envelope")
    if type(auth.get("threshold")) is not int or auth["threshold"] != THRESHOLD:
        raise AssertionError("invalid monitor-set rotation authorization threshold")
    if auth.get("payload_sha256") != sha256(rotation_raw) or auth.get("production") is not False:
        raise AssertionError("monitor-set rotation authorization payload mismatch")
    rows = auth.get("monitors")
    if not isinstance(rows, list) or not (THRESHOLD <= len(rows) <= len(OLD_PINNED_MONITORS)):
        raise AssertionError("invalid monitor-set rotation authorization size")
    if not all(isinstance(row, dict) and frozenset(row) == AUTH_MONITOR_KEYS for row in rows):
        raise AssertionError("invalid monitor-set rotation authorization entry")
    ids = [row["monitor_id"] for row in rows]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("rotation monitor ids must be unique and sorted")
    if any(monitor_id not in OLD_PINNED_MONITORS for monitor_id in ids):
        raise AssertionError("unknown monitor-set rotation authorizer")
    message = rotation_message(rotation_raw)
    for row in rows:
        material_verify.ed25519_verify(
            OLD_PINNED_MONITORS[row["monitor_id"]],
            material_verify.decode_signature(row["signature"]),
            message,
        )


def validate_successor_report(report: dict, target: dict, set_sha: str) -> dict:
    if not isinstance(report, dict) or frozenset(report) != REPORT_KEYS:
        raise AssertionError("invalid successor monitor report fields")
    if report.get("schema") != SUCCESSOR_REPORT_SCHEMA or report.get("algorithm") != ALGORITHM:
        raise AssertionError("invalid successor monitor report envelope")
    statement = report.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != STATEMENT_KEYS:
        raise AssertionError("invalid successor monitor statement fields")
    if statement.get("schema") != SUCCESSOR_STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError("invalid successor monitor statement boundary")
    monitor_id = statement.get("monitor_id")
    if not isinstance(monitor_id, str) or monitor_id not in NEW_PINNED_MONITORS:
        raise AssertionError("unknown successor checkpoint monitor")
    if monitor_id == REVOKED_MONITOR_ID:
        raise AssertionError("revoked checkpoint monitor resurrected")
    if statement.get("monitor_set_sequence") != NEW_SET_SEQUENCE or statement.get("monitor_set_sha256") != set_sha:
        raise AssertionError("successor monitor-set epoch mismatch")
    material_verify.ed25519_verify(
        NEW_PINNED_MONITORS[monitor_id],
        material_verify.decode_signature(report["signature"]),
        successor_message(statement),
    )
    return statement


def statement_matches_target(statement: dict, target: dict) -> bool:
    return all(statement.get(key) == target[key] for key in TARGET_KEYS)


def validate_successor_bundle(bundle: dict, target: dict) -> None:
    set_sha = sha256(canonical(new_monitor_set()))
    if frozenset(bundle) != BUNDLE_KEYS or bundle.get("schema") != SUCCESSOR_BUNDLE_SCHEMA:
        raise AssertionError("invalid successor monitor bundle fields")
    if bundle.get("monitor_set_sequence") != NEW_SET_SEQUENCE or bundle.get("monitor_set_sha256") != set_sha:
        raise AssertionError("successor monitor bundle set mismatch")
    if type(bundle.get("threshold")) is not int or bundle["threshold"] != THRESHOLD:
        raise AssertionError("invalid successor monitor threshold")
    if bundle.get("production") is not False:
        raise AssertionError("production successor monitor bundle forbidden in RUST-043")
    reports = bundle.get("reports")
    if not isinstance(reports, list) or not (THRESHOLD <= len(reports) <= len(NEW_PINNED_MONITORS)):
        raise AssertionError("invalid successor monitor report count")
    statements = [validate_successor_report(report, target, set_sha) for report in reports]
    ids = [statement["monitor_id"] for statement in statements]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("successor checkpoint monitor ids must be unique and sorted")
    matching = 0
    for statement in statements:
        same_parent = (
            statement["observer_set_sequence"] == target["observer_set_sequence"]
            and statement["previous_checkpoint_sha256"] == target["previous_checkpoint_sha256"]
        )
        exact = statement_matches_target(statement, target)
        if same_parent and not exact:
            raise AssertionError("observed successor monitor same-parent observer-journal fork")
        if not exact:
            raise AssertionError("successor monitor report does not match canonical observer-journal checkpoint")
        matching += 1
    if matching < THRESHOLD:
        raise AssertionError("successor monitor quorum below threshold")


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
    monitor_set_rotation_path: Path,
    rotation_auth_path: Path,
    successor_monitor_bundle_path: Path,
    expected_source_sha: str,
    required_floor_text: str,
) -> None:
    monitor_verify.verify(
        final_state_path, external_floor_path, first_witness_rotation_path, first_witness_auth_path,
        first_witness_quorum_path, second_witness_rotation_path, second_witness_auth_path,
        final_witness_quorum_path, prefix_witness_journal_path, prefix_witness_checkpoint_path,
        final_witness_journal_path, final_witness_checkpoint_path, old_observer_bundle_path,
        first_observer_rotation_path, first_observer_auth_path, first_observer_successor_path,
        second_observer_rotation_path, second_observer_auth_path, final_observer_bundle_path,
        prefix_observer_journal_path, prefix_observer_checkpoint_path, final_observer_journal_path,
        final_observer_checkpoint_path, old_monitor_bundle_path, expected_source_sha, required_floor_text,
    )
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(final_observer_checkpoint_path, "final observer checkpoint")
    target = monitor_verify.checkpoint_target(final_checkpoint_raw, final_checkpoint["statement"])
    old_bundle_raw, _ = floor_verify.load_canonical(old_monitor_bundle_path, "predecessor monitor bundle")
    rotation_raw, rotation = floor_verify.load_canonical(monitor_set_rotation_path, "monitor-set rotation")
    _, auth = floor_verify.load_canonical(rotation_auth_path, "monitor-set rotation authorization")
    _, successor = floor_verify.load_canonical(successor_monitor_bundle_path, "successor monitor bundle")
    validate_rotation(rotation, target, old_bundle_raw, expected_source_sha)
    validate_rotation_auth(auth, rotation_raw)
    validate_successor_bundle(successor, target)
    ids = ",".join(report["statement"]["monitor_id"] for report in successor["reports"])
    print(
        "RUST-043 monitor-set rotation continuity: GREEN "
        f"source={expected_source_sha} revoked={REVOKED_MONITOR_ID} successor={ids}"
    )


def main() -> None:
    if len(sys.argv) != 31 or sys.argv[1] != "verify":
        raise SystemExit("usage: rust_043_monitor_set_rotation_verify.py verify ... OLD_MONITOR_BUNDLE ROTATION AUTH SUCCESSOR SOURCE_SHA REQUIRED_FLOOR")
    paths = [Path(value) for value in sys.argv[2:-2]]
    verify(*paths, sys.argv[-2], sys.argv[-1])


if __name__ == "__main__":
    main()
