#!/usr/bin/env python3
"""RUST-059: TEST-ONLY observer-rotation-journal monitor-set rotation verifier."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_058_observer_rotation_journal_monitor_verify as monitor_verify

MONITOR_SET_SCHEMA = "axven-native-journal-monitor-journal-observer-rotation-journal-monitor-set-v1"
ROTATION_SCHEMA = "axven-native-journal-monitor-journal-observer-rotation-journal-monitor-set-rotation-v1"
ROTATION_AUTH_SCHEMA = "axven-native-journal-monitor-journal-observer-rotation-journal-monitor-set-rotation-quorum-v1"
ROTATION_PAYLOAD_TYPE = "application/vnd.axven.native-journal-monitor-journal-observer-rotation-journal-monitor-set-rotation.v1+json"
SUCCESSOR_BUNDLE_SCHEMA = "axven-native-journal-monitor-journal-observer-rotation-journal-checkpoint-monitor-bundle-v2"
SUCCESSOR_REPORT_SCHEMA = "axven-native-journal-monitor-journal-observer-rotation-journal-checkpoint-monitor-report-v2"
SUCCESSOR_STATEMENT_SCHEMA = "axven-native-journal-monitor-journal-observer-rotation-journal-checkpoint-monitor-statement-v2"
ROTATION_DOMAIN = b"AXVEN_NATIVE_OBSERVER_ROTATION_JOURNAL_MONITOR_SET_ROTATION_V1\x00"
SUCCESSOR_DOMAIN = b"AXVEN_NATIVE_OBSERVER_ROTATION_JOURNAL_CHECKPOINT_MONITOR_V2\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2
OLD_SET_SEQUENCE = 0
NEW_SET_SEQUENCE = 1
M4_ID = "rust-059-test-only-observer-rotation-journal-monitor-4-v1"
M4_PUBLIC_KEY = bytes.fromhex("fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618")
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
    "predecessor_monitor_bundle_sha256",
    "observer_rotation_journal_checkpoint_sha256",
    "observer_rotation_journal_checkpoint_statement_sha256",
    "observed_checkpoint_sha256", "journal_observer_checkpoint_sha256",
    "monitor_journal_checkpoint_sha256", "monitor_journal_checkpoint_statement_sha256",
    "activation_source_commit", "production",
})
AUTH_KEYS = frozenset({
    "schema", "algorithm", "threshold", "payload_type", "payload_sha256",
    "monitors", "production",
})
AUTH_MONITOR_KEYS = frozenset({"monitor_id", "signature"})
SUCCESSOR_BUNDLE_KEYS = frozenset({
    "schema", "monitor_set_sequence", "monitor_set_sha256", "threshold", "reports", "production",
})
SUCCESSOR_REPORT_KEYS = frozenset({"schema", "algorithm", "statement", "signature"})
SUCCESSOR_STATEMENT_KEYS = frozenset({
    "schema", "monitor_id", "monitor_set_sequence", "monitor_set_sha256",
    "observer_rotation_journal_checkpoint_sha256",
    "observer_rotation_journal_checkpoint_statement_sha256",
    "observer_set_sequence", "observer_set_sha256", "entry_count",
    "journal_sha256", "head_entry_sha256", "previous_checkpoint_sha256",
    "observed_checkpoint_sha256", "observed_checkpoint_statement_sha256",
    "journal_observer_checkpoint_sha256", "monitor_journal_checkpoint_sha256",
    "monitor_journal_checkpoint_statement_sha256", "activation_source_commit", "production",
})


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


def rotation_message(rotation_raw: bytes) -> bytes:
    return ROTATION_DOMAIN + len(rotation_raw).to_bytes(8, "big") + rotation_raw


def successor_message(statement: dict) -> bytes:
    raw = canonical(statement)
    return SUCCESSOR_DOMAIN + len(raw).to_bytes(8, "big") + raw


def validate_rotation(rotation: dict, old_bundle_raw: bytes, target: dict, source_sha: str) -> None:
    if not isinstance(rotation, dict) or frozenset(rotation) != ROTATION_KEYS or rotation.get("schema") != ROTATION_SCHEMA:
        raise AssertionError("invalid observer-rotation-journal monitor rotation fields")
    if type(rotation.get("sequence")) is not int or rotation["sequence"] != NEW_SET_SEQUENCE:
        raise AssertionError("invalid observer-rotation-journal monitor rotation sequence")
    if rotation.get("from_set_sha256") != sha256(canonical(old_monitor_set())):
        raise AssertionError("observer-rotation-journal monitor predecessor set mismatch")
    if rotation.get("to_set") != new_monitor_set():
        raise AssertionError("unexpected successor observer-rotation-journal monitor set")
    if rotation.get("revoked_monitor_ids") != [REVOKED_MONITOR_ID]:
        raise AssertionError("observer-rotation-journal monitor revocation continuity mismatch")
    if rotation.get("predecessor_monitor_bundle_sha256") != sha256(old_bundle_raw):
        raise AssertionError("predecessor observer-rotation-journal monitor bundle mismatch")
    for key in (
        "observer_rotation_journal_checkpoint_sha256",
        "observer_rotation_journal_checkpoint_statement_sha256",
        "observed_checkpoint_sha256",
        "journal_observer_checkpoint_sha256",
        "monitor_journal_checkpoint_sha256",
        "monitor_journal_checkpoint_statement_sha256",
    ):
        if rotation.get(key) != target[key]:
            raise AssertionError(f"rotation inherited checkpoint binding mismatch: {key}")
    if rotation.get("activation_source_commit") != source_sha:
        raise AssertionError("observer-rotation-journal monitor rotation source mismatch")
    if rotation.get("production") is not False:
        raise AssertionError("production observer-rotation-journal monitor rotation forbidden in RUST-059")


def validate_rotation_auth(auth: dict, rotation_raw: bytes) -> None:
    if not isinstance(auth, dict) or frozenset(auth) != AUTH_KEYS or auth.get("schema") != ROTATION_AUTH_SCHEMA:
        raise AssertionError("invalid monitor rotation authorization fields")
    if auth.get("algorithm") != ALGORITHM or auth.get("payload_type") != ROTATION_PAYLOAD_TYPE:
        raise AssertionError("invalid monitor rotation authorization envelope")
    if type(auth.get("threshold")) is not int or auth["threshold"] != THRESHOLD:
        raise AssertionError("invalid monitor rotation authorization threshold")
    if auth.get("payload_sha256") != sha256(rotation_raw) or auth.get("production") is not False:
        raise AssertionError("monitor rotation authorization payload mismatch")
    monitors = auth.get("monitors")
    if not isinstance(monitors, list) or not (THRESHOLD <= len(monitors) <= len(OLD_PINNED_MONITORS)):
        raise AssertionError("invalid monitor rotation authorization size")
    if not all(isinstance(item, dict) and frozenset(item) == AUTH_MONITOR_KEYS for item in monitors):
        raise AssertionError("invalid monitor rotation authorization entry")
    ids = [item["monitor_id"] for item in monitors]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("monitor rotation authorizer ids must be unique and sorted")
    if any(monitor_id not in OLD_PINNED_MONITORS for monitor_id in ids):
        raise AssertionError("unknown monitor rotation authorizer")
    message = rotation_message(rotation_raw)
    for item in monitors:
        material_verify.ed25519_verify(
            OLD_PINNED_MONITORS[item["monitor_id"]],
            material_verify.decode_signature(item["signature"]),
            message,
        )


def validate_successor_report(report: dict, set_sha: str) -> dict:
    if not isinstance(report, dict) or frozenset(report) != SUCCESSOR_REPORT_KEYS:
        raise AssertionError("invalid successor monitor report fields")
    if report.get("schema") != SUCCESSOR_REPORT_SCHEMA or report.get("algorithm") != ALGORITHM:
        raise AssertionError("invalid successor monitor report envelope")
    statement = report.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != SUCCESSOR_STATEMENT_KEYS:
        raise AssertionError("invalid successor monitor statement fields")
    if statement.get("schema") != SUCCESSOR_STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError("invalid successor monitor statement boundary")
    monitor_id = statement.get("monitor_id")
    if not isinstance(monitor_id, str) or monitor_id not in NEW_PINNED_MONITORS:
        raise AssertionError("unknown successor observer-rotation-journal monitor")
    if monitor_id == REVOKED_MONITOR_ID:
        raise AssertionError("revoked observer-rotation-journal monitor resurrected")
    if statement.get("monitor_set_sequence") != NEW_SET_SEQUENCE or statement.get("monitor_set_sha256") != set_sha:
        raise AssertionError("successor monitor-set epoch mismatch")
    material_verify.ed25519_verify(
        NEW_PINNED_MONITORS[monitor_id],
        material_verify.decode_signature(report["signature"]),
        successor_message(statement),
    )
    return statement


def validate_successor_bundle(bundle: dict, target: dict) -> None:
    set_sha = sha256(canonical(new_monitor_set()))
    if not isinstance(bundle, dict) or frozenset(bundle) != SUCCESSOR_BUNDLE_KEYS or bundle.get("schema") != SUCCESSOR_BUNDLE_SCHEMA:
        raise AssertionError("invalid successor observer-rotation-journal monitor bundle fields")
    if bundle.get("monitor_set_sequence") != NEW_SET_SEQUENCE or bundle.get("monitor_set_sha256") != set_sha:
        raise AssertionError("successor monitor bundle set mismatch")
    if type(bundle.get("threshold")) is not int or bundle["threshold"] != THRESHOLD:
        raise AssertionError("invalid successor monitor threshold")
    if bundle.get("production") is not False:
        raise AssertionError("production successor monitoring forbidden in RUST-059")
    reports = bundle.get("reports")
    if not isinstance(reports, list) or not (THRESHOLD <= len(reports) <= len(NEW_PINNED_MONITORS)):
        raise AssertionError("invalid successor monitor report count")
    statements = [validate_successor_report(report, set_sha) for report in reports]
    ids = [statement["monitor_id"] for statement in statements]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("successor monitor ids must be unique and sorted")
    for statement in statements:
        if statement["activation_source_commit"] != target["activation_source_commit"]:
            raise AssertionError("successor monitor source mismatch")
        same_parent = (
            statement["observer_set_sequence"] == target["observer_set_sequence"]
            and statement["previous_checkpoint_sha256"] == target["previous_checkpoint_sha256"]
        )
        exact = all(statement[key] == target[key] for key in monitor_verify.TARGET_KEYS)
        if same_parent and not exact:
            raise AssertionError("observed successor same-parent observer-rotation-journal checkpoint fork")
        if not exact:
            raise AssertionError("successor monitor report does not match canonical observer-rotation-journal checkpoint")


def verify(*args) -> None:
    if len(args) != 73:
        raise AssertionError("unexpected RUST-059 verifier argument count")
    *base_paths, old_bundle_path, rotation_path, auth_path, successor_path, expected_source_sha, required_floor_text = args
    if len(base_paths) != 67:
        raise AssertionError("unexpected RUST-059 base path count")
    monitor_verify.verify(*base_paths, old_bundle_path, expected_source_sha, required_floor_text)

    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(
        base_paths[-1], "final observer-rotation checkpoint"
    )
    target = monitor_verify.checkpoint_target(final_checkpoint_raw, final_checkpoint["statement"])
    if target["activation_source_commit"] != expected_source_sha:
        raise AssertionError("RUST-059 checkpoint source mismatch")
    old_bundle_raw, _ = floor_verify.load_canonical(old_bundle_path, "predecessor monitor bundle")
    rotation_raw, rotation = floor_verify.load_canonical(rotation_path, "monitor-set rotation")
    _, auth = floor_verify.load_canonical(auth_path, "monitor-set rotation authorization")
    _, successor = floor_verify.load_canonical(successor_path, "successor monitor bundle")
    validate_rotation(rotation, old_bundle_raw, target, expected_source_sha)
    validate_rotation_auth(auth, rotation_raw)
    validate_successor_bundle(successor, target)
    ids = ",".join(report["statement"]["monitor_id"] for report in successor["reports"])
    print(
        "RUST-059 observer-rotation-journal monitor-set rotation: GREEN "
        f"source={expected_source_sha} revoked={REVOKED_MONITOR_ID} successor={ids}"
    )


def main() -> None:
    if len(sys.argv) != 75 or sys.argv[1] != "verify":
        raise SystemExit(
            "usage: rust_059_observer_rotation_journal_monitor_set_rotation_verify.py verify "
            "... OLD_BUNDLE ROTATION AUTH SUCCESSOR SOURCE_SHA REQUIRED_FLOOR"
        )
    paths = [Path(value) for value in sys.argv[2:-2]]
    verify(*paths, sys.argv[-2], sys.argv[-1])


if __name__ == "__main__":
    main()
