#!/usr/bin/env python3
"""RUST-052: TEST-ONLY multi-step journal-monitor set rotation continuity."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_050_journal_observer_journal_monitor_verify as monitor_verify
import rust_051_journal_monitor_set_rotation_verify as rotation1_verify

ROTATION_SCHEMA = "axven-native-journal-observer-journal-monitor-set-rotation-v2"
ROTATION_AUTH_SCHEMA = "axven-native-journal-observer-journal-monitor-set-rotation-quorum-v2"
ROTATION_PAYLOAD_TYPE = "application/vnd.axven.native-journal-observer-journal-monitor-set-rotation.v2+json"
FINAL_BUNDLE_SCHEMA = "axven-native-journal-observer-journal-checkpoint-monitor-bundle-v3"
FINAL_REPORT_SCHEMA = "axven-native-journal-observer-journal-checkpoint-monitor-report-v3"
FINAL_STATEMENT_SCHEMA = "axven-native-journal-observer-journal-checkpoint-monitor-statement-v3"
ROTATION_DOMAIN = b"AXVEN_NATIVE_JOURNAL_OBSERVER_JOURNAL_MONITOR_SET_ROTATION_V2\x00"
FINAL_DOMAIN = b"AXVEN_NATIVE_JOURNAL_OBSERVER_JOURNAL_CHECKPOINT_MONITOR_V3\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2
PREDECESSOR_SET_SEQUENCE = 1
FINAL_SET_SEQUENCE = 2
JM5_ID = "rust-052-test-only-journal-monitor-5-v1"
JM5_PUBLIC_KEY = bytes.fromhex("1bee74bb8f513f1b5357bc477c886ad96949d04740ccd13a22f912edf00dfe27")
CUMULATIVE_REVOKED_MONITOR_IDS = [
    rotation1_verify.REVOKED_MONITOR_ID,
    monitor_verify.MONITOR_2_ID,
]
PREDECESSOR_PINNED_MONITORS = dict(rotation1_verify.NEW_PINNED_MONITORS)
FINAL_PINNED_MONITORS = {
    monitor_verify.MONITOR_3_ID: monitor_verify.MONITOR_3_PUBLIC_KEY,
    rotation1_verify.JM4_ID: rotation1_verify.JM4_PUBLIC_KEY,
    JM5_ID: JM5_PUBLIC_KEY,
}

ROTATION_KEYS = frozenset({
    "schema", "sequence", "from_set_sha256", "to_set", "cumulative_revoked_monitor_ids",
    "predecessor_rotation_sha256", "predecessor_rotation_auth_sha256",
    "predecessor_successor_bundle_sha256", "journal_observer_checkpoint_sha256",
    "monitor_journal_checkpoint_sha256", "monitor_journal_checkpoint_statement_sha256",
    "activation_source_commit", "production",
})
AUTH_KEYS = frozenset({
    "schema", "algorithm", "threshold", "payload_type", "payload_sha256",
    "monitors", "production",
})
AUTH_MONITOR_KEYS = frozenset({"monitor_id", "signature"})
FINAL_BUNDLE_KEYS = frozenset({
    "schema", "monitor_set_sequence", "monitor_set_sha256", "threshold", "reports", "production",
})
FINAL_REPORT_KEYS = frozenset({"schema", "algorithm", "statement", "signature"})
FINAL_STATEMENT_KEYS = frozenset({
    "schema", "monitor_id", "monitor_set_sequence", "monitor_set_sha256",
    "journal_observer_checkpoint_sha256", "observer_set_sequence", "observer_set_sha256",
    "entry_count", "journal_sha256", "head_entry_sha256", "previous_checkpoint_sha256",
    "monitor_journal_checkpoint_sha256", "monitor_journal_checkpoint_statement_sha256",
    "activation_source_commit", "production",
})
TARGET_KEYS = frozenset(monitor_verify.TARGET_KEYS)


def canonical(value: dict) -> bytes:
    return material_verify.canonical(value)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def final_monitor_set() -> dict:
    return rotation1_verify.monitor_set(FINAL_SET_SEQUENCE, FINAL_PINNED_MONITORS)


def rotation_message(raw: bytes) -> bytes:
    return ROTATION_DOMAIN + len(raw).to_bytes(8, "big") + raw


def final_message(statement: dict) -> bytes:
    raw = canonical(statement)
    return FINAL_DOMAIN + len(raw).to_bytes(8, "big") + raw


def validate_rotation(
    rotation: dict,
    target: dict,
    first_rotation_raw: bytes,
    first_auth_raw: bytes,
    first_successor_raw: bytes,
    source_sha: str,
) -> None:
    if not isinstance(rotation, dict) or frozenset(rotation) != ROTATION_KEYS or rotation.get("schema") != ROTATION_SCHEMA:
        raise AssertionError("invalid second journal-monitor rotation fields")
    if type(rotation.get("sequence")) is not int or rotation["sequence"] != FINAL_SET_SEQUENCE:
        raise AssertionError("invalid second journal-monitor rotation sequence")
    if rotation.get("from_set_sha256") != sha256(canonical(rotation1_verify.new_monitor_set())):
        raise AssertionError("second journal-monitor predecessor set mismatch")
    if rotation.get("to_set") != final_monitor_set():
        raise AssertionError("unexpected final journal-monitor set")
    if rotation.get("cumulative_revoked_monitor_ids") != CUMULATIVE_REVOKED_MONITOR_IDS:
        raise AssertionError("cumulative journal-monitor revocation continuity mismatch")
    if rotation.get("predecessor_rotation_sha256") != sha256(first_rotation_raw):
        raise AssertionError("predecessor journal-monitor rotation digest mismatch")
    if rotation.get("predecessor_rotation_auth_sha256") != sha256(first_auth_raw):
        raise AssertionError("predecessor journal-monitor rotation authorization digest mismatch")
    if rotation.get("predecessor_successor_bundle_sha256") != sha256(first_successor_raw):
        raise AssertionError("predecessor successor journal-monitor bundle digest mismatch")
    if rotation.get("journal_observer_checkpoint_sha256") != target["journal_observer_checkpoint_sha256"]:
        raise AssertionError("second journal-monitor journal-observer checkpoint binding mismatch")
    if rotation.get("monitor_journal_checkpoint_sha256") != target["monitor_journal_checkpoint_sha256"]:
        raise AssertionError("second journal-monitor monitor-journal checkpoint binding mismatch")
    if rotation.get("monitor_journal_checkpoint_statement_sha256") != target["monitor_journal_checkpoint_statement_sha256"]:
        raise AssertionError("second journal-monitor checkpoint-statement binding mismatch")
    if rotation.get("activation_source_commit") != source_sha:
        raise AssertionError("second journal-monitor rotation source mismatch")
    if rotation.get("production") is not False:
        raise AssertionError("production second journal-monitor rotation forbidden in RUST-052")


def validate_rotation_auth(auth: dict, rotation_raw: bytes) -> None:
    if not isinstance(auth, dict) or frozenset(auth) != AUTH_KEYS or auth.get("schema") != ROTATION_AUTH_SCHEMA:
        raise AssertionError("invalid second journal-monitor rotation authorization fields")
    if auth.get("algorithm") != ALGORITHM or auth.get("payload_type") != ROTATION_PAYLOAD_TYPE:
        raise AssertionError("invalid second journal-monitor rotation authorization envelope")
    if type(auth.get("threshold")) is not int or auth["threshold"] != THRESHOLD:
        raise AssertionError("invalid second journal-monitor rotation authorization threshold")
    if auth.get("payload_sha256") != sha256(rotation_raw) or auth.get("production") is not False:
        raise AssertionError("second journal-monitor rotation authorization payload mismatch")
    rows = auth.get("monitors")
    if not isinstance(rows, list) or not (THRESHOLD <= len(rows) <= len(PREDECESSOR_PINNED_MONITORS)):
        raise AssertionError("invalid second journal-monitor rotation authorization size")
    if not all(isinstance(row, dict) and frozenset(row) == AUTH_MONITOR_KEYS for row in rows):
        raise AssertionError("invalid second journal-monitor rotation authorization entry")
    ids = [row["monitor_id"] for row in rows]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("second journal-monitor rotation ids must be unique and sorted")
    if any(monitor_id not in PREDECESSOR_PINNED_MONITORS for monitor_id in ids):
        raise AssertionError("unknown second journal-monitor rotation authorizer")
    message = rotation_message(rotation_raw)
    for row in rows:
        material_verify.ed25519_verify(
            PREDECESSOR_PINNED_MONITORS[row["monitor_id"]],
            material_verify.decode_signature(row["signature"]),
            message,
        )


def validate_final_report(report: dict, set_sha: str) -> dict:
    if not isinstance(report, dict) or frozenset(report) != FINAL_REPORT_KEYS:
        raise AssertionError("invalid final journal-monitor report fields")
    if report.get("schema") != FINAL_REPORT_SCHEMA or report.get("algorithm") != ALGORITHM:
        raise AssertionError("invalid final journal-monitor report envelope")
    statement = report.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != FINAL_STATEMENT_KEYS:
        raise AssertionError("invalid final journal-monitor statement fields")
    if statement.get("schema") != FINAL_STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError("invalid final journal-monitor statement boundary")
    monitor_id = statement.get("monitor_id")
    if not isinstance(monitor_id, str) or monitor_id not in FINAL_PINNED_MONITORS:
        raise AssertionError("unknown final journal monitor")
    if monitor_id in CUMULATIVE_REVOKED_MONITOR_IDS:
        raise AssertionError("revoked journal monitor resurrected in final set")
    if statement.get("monitor_set_sequence") != FINAL_SET_SEQUENCE or statement.get("monitor_set_sha256") != set_sha:
        raise AssertionError("final journal-monitor set epoch mismatch")
    material_verify.ed25519_verify(
        FINAL_PINNED_MONITORS[monitor_id],
        material_verify.decode_signature(report["signature"]),
        final_message(statement),
    )
    return statement


def statement_matches_target(statement: dict, target: dict) -> bool:
    return all(statement.get(key) == target[key] for key in TARGET_KEYS)


def validate_final_bundle(bundle: dict, target: dict) -> None:
    set_sha = sha256(canonical(final_monitor_set()))
    if not isinstance(bundle, dict) or frozenset(bundle) != FINAL_BUNDLE_KEYS or bundle.get("schema") != FINAL_BUNDLE_SCHEMA:
        raise AssertionError("invalid final journal-monitor bundle fields")
    if bundle.get("monitor_set_sequence") != FINAL_SET_SEQUENCE or bundle.get("monitor_set_sha256") != set_sha:
        raise AssertionError("final journal-monitor bundle set mismatch")
    if type(bundle.get("threshold")) is not int or bundle["threshold"] != THRESHOLD:
        raise AssertionError("invalid final journal-monitor threshold")
    if bundle.get("production") is not False:
        raise AssertionError("production final journal monitoring forbidden in RUST-052")
    reports = bundle.get("reports")
    if not isinstance(reports, list) or not (THRESHOLD <= len(reports) <= len(FINAL_PINNED_MONITORS)):
        raise AssertionError("invalid final journal-monitor report count")
    statements = [validate_final_report(report, set_sha) for report in reports]
    ids = [statement["monitor_id"] for statement in statements]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("final journal-monitor ids must be unique and sorted")
    for statement in statements:
        same_parent = (
            statement["observer_set_sequence"] == target["observer_set_sequence"]
            and statement["previous_checkpoint_sha256"] == target["previous_checkpoint_sha256"]
        )
        exact = statement_matches_target(statement, target)
        if same_parent and not exact:
            raise AssertionError("observed final journal-monitor same-parent journal-observer-journal checkpoint fork")
        if not exact:
            raise AssertionError("final journal-monitor report does not match canonical journal-observer checkpoint")


def verify(*args) -> None:
    if len(args) != 54:
        raise AssertionError("unexpected RUST-052 verifier argument count")
    *path_args, expected_source_sha, required_floor_text = args
    if len(path_args) != 52:
        raise AssertionError("unexpected RUST-052 path count")

    base_paths = path_args[:45]
    old_bundle_path, first_rotation_path, first_auth_path, first_successor_path = path_args[45:49]
    second_rotation_path, second_auth_path, final_bundle_path = path_args[49:52]

    rotation1_verify.verify(
        *base_paths,
        old_bundle_path, first_rotation_path, first_auth_path, first_successor_path,
        expected_source_sha, required_floor_text,
    )

    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(
        base_paths[-1], "final journal-observer checkpoint"
    )
    target = monitor_verify.checkpoint_target(final_checkpoint_raw, final_checkpoint["statement"])
    if target["activation_source_commit"] != expected_source_sha:
        raise AssertionError("RUST-052 checkpoint source mismatch")

    first_rotation_raw, _ = floor_verify.load_canonical(first_rotation_path, "first journal-monitor rotation")
    first_auth_raw, _ = floor_verify.load_canonical(first_auth_path, "first journal-monitor rotation authorization")
    first_successor_raw, _ = floor_verify.load_canonical(first_successor_path, "first journal-monitor successor bundle")
    second_rotation_raw, second_rotation = floor_verify.load_canonical(second_rotation_path, "second journal-monitor rotation")
    _, second_auth = floor_verify.load_canonical(second_auth_path, "second journal-monitor rotation authorization")
    _, final_bundle = floor_verify.load_canonical(final_bundle_path, "final journal-monitor bundle")

    validate_rotation(
        second_rotation, target, first_rotation_raw, first_auth_raw, first_successor_raw, expected_source_sha
    )
    validate_rotation_auth(second_auth, second_rotation_raw)
    validate_final_bundle(final_bundle, target)

    ids = ",".join(report["statement"]["monitor_id"] for report in final_bundle["reports"])
    print(
        "RUST-052 multi-step journal-monitor set rotation: GREEN "
        f"source={expected_source_sha} sequence=2 "
        f"revoked={','.join(CUMULATIVE_REVOKED_MONITOR_IDS)} final={ids}"
    )


def main() -> None:
    if len(sys.argv) != 56 or sys.argv[1] != "verify":
        raise SystemExit(
            "usage: rust_052_multistep_journal_monitor_rotation_verify.py verify "
            "... FIRST_ROT AUTH SUCCESSOR SECOND_ROT AUTH FINAL_BUNDLE SOURCE_SHA REQUIRED_FLOOR"
        )
    paths = [Path(value) for value in sys.argv[2:-2]]
    verify(*paths, sys.argv[-2], sys.argv[-1])


if __name__ == "__main__":
    main()
