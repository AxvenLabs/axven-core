#!/usr/bin/env python3
"""RUST-080: TEST-ONLY second observer rotation for the RUST-077 checkpoint observers."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_078_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_verify as observer_verify
import rust_079_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify as rotation1_verify

ROTATION_SCHEMA = "axven-native-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-observer-set-rotation-v2"
ROTATION_AUTH_SCHEMA = "axven-native-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-observer-set-rotation-quorum-v2"
ROTATION_PAYLOAD_TYPE = "application/vnd.axven.native-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-observer-set-rotation.v2+json"
FINAL_BUNDLE_SCHEMA = "axven-native-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-checkpoint-observation-bundle-v3"
FINAL_REPORT_SCHEMA = "axven-native-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-checkpoint-observation-v3"
FINAL_STATEMENT_SCHEMA = "axven-native-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-checkpoint-observation-statement-v3"
ROTATION_DOMAIN = b"AXVEN_NATIVE_MONITOR_ROTATION_JOURNAL_OBSERVER_ROTATION_JOURNAL_MONITOR_ROTATION_JOURNAL_OBSERVER_SET_ROTATION_V2\x00"
FINAL_DOMAIN = b"AXVEN_NATIVE_MONITOR_ROTATION_JOURNAL_OBSERVER_ROTATION_JOURNAL_MONITOR_ROTATION_JOURNAL_CHECKPOINT_OBSERVATION_V3\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2
PREDECESSOR_SET_SEQUENCE = 1
FINAL_SET_SEQUENCE = 2

O5_ID = "rust-080-test-only-monitor-rotation-journal-observer-rotation-journal-monitor-rotation-journal-observer-5-v1"
O5_PUBLIC_KEY = bytes.fromhex("772c8a442b7db06e166cfbc1ccbcbcde6f3eba76a4e98ef3ffc519502237d6ef")
CUMULATIVE_REVOKED_OBSERVER_IDS = [
    rotation1_verify.REVOKED_OBSERVER_ID,
    observer_verify.OBSERVER_2_ID,
]
PREDECESSOR_PINNED_OBSERVERS = dict(rotation1_verify.NEW_PINNED_OBSERVERS)
FINAL_PINNED_OBSERVERS = {
    observer_verify.OBSERVER_3_ID: observer_verify.OBSERVER_3_PUBLIC_KEY,
    rotation1_verify.O4_ID: rotation1_verify.O4_PUBLIC_KEY,
    O5_ID: O5_PUBLIC_KEY,
}

ROTATION_KEYS = frozenset({
    "schema", "sequence", "from_set_sha256", "to_set",
    "cumulative_revoked_observer_ids", "predecessor_rotation_sha256",
    "predecessor_rotation_auth_sha256", "predecessor_successor_bundle_sha256",
    *observer_verify.TARGET_KEYS, "production",
})
AUTH_KEYS = frozenset({
    "schema", "algorithm", "threshold", "payload_type", "payload_sha256",
    "observers", "production",
})
AUTH_OBSERVER_KEYS = frozenset({"observer_id", "signature"})
FINAL_BUNDLE_KEYS = frozenset({
    "schema", "observer_set_sequence", "observer_set_sha256", "threshold",
    "reports", "production",
})
FINAL_REPORT_KEYS = frozenset({"schema", "algorithm", "statement", "signature"})
FINAL_STATEMENT_KEYS = frozenset({
    "schema", "observer_id", "observer_set_sequence", "observer_set_sha256",
    *observer_verify.TARGET_KEYS, "production",
})
TARGET_KEYS = frozenset(observer_verify.TARGET_KEYS)


def canonical(value: dict) -> bytes:
    return material_verify.canonical(value)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def final_observer_set() -> dict:
    return rotation1_verify.observer_set(FINAL_SET_SEQUENCE, FINAL_PINNED_OBSERVERS)


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
) -> None:
    if (
        not isinstance(rotation, dict)
        or frozenset(rotation) != ROTATION_KEYS
        or rotation.get("schema") != ROTATION_SCHEMA
    ):
        raise AssertionError("invalid RUST-080 second observer rotation fields")
    if type(rotation.get("sequence")) is not int or rotation["sequence"] != FINAL_SET_SEQUENCE:
        raise AssertionError("invalid RUST-080 second observer rotation sequence")
    if rotation.get("from_set_sha256") != sha256(canonical(rotation1_verify.new_observer_set())):
        raise AssertionError("RUST-080 predecessor observer set mismatch")
    if rotation.get("to_set") != final_observer_set():
        raise AssertionError("unexpected RUST-080 final observer set")
    if rotation.get("cumulative_revoked_observer_ids") != CUMULATIVE_REVOKED_OBSERVER_IDS:
        raise AssertionError("RUST-080 cumulative observer revocation mismatch")
    if rotation.get("predecessor_rotation_sha256") != sha256(first_rotation_raw):
        raise AssertionError("RUST-080 predecessor rotation digest mismatch")
    if rotation.get("predecessor_rotation_auth_sha256") != sha256(first_auth_raw):
        raise AssertionError("RUST-080 predecessor rotation authorization digest mismatch")
    if rotation.get("predecessor_successor_bundle_sha256") != sha256(first_successor_raw):
        raise AssertionError("RUST-080 predecessor successor bundle digest mismatch")
    for key in TARGET_KEYS:
        if rotation.get(key) != target[key]:
            raise AssertionError(f"RUST-080 inherited target binding mismatch: {key}")
    if rotation.get("production") is not False:
        raise AssertionError("production second observer rotation forbidden in RUST-080")


def validate_rotation_auth(auth: dict, rotation_raw: bytes) -> None:
    if (
        not isinstance(auth, dict)
        or frozenset(auth) != AUTH_KEYS
        or auth.get("schema") != ROTATION_AUTH_SCHEMA
    ):
        raise AssertionError("invalid RUST-080 rotation authorization fields")
    if auth.get("algorithm") != ALGORITHM or auth.get("payload_type") != ROTATION_PAYLOAD_TYPE:
        raise AssertionError("invalid RUST-080 rotation authorization envelope")
    if type(auth.get("threshold")) is not int or auth["threshold"] != THRESHOLD:
        raise AssertionError("invalid RUST-080 rotation authorization threshold")
    if auth.get("payload_sha256") != sha256(rotation_raw) or auth.get("production") is not False:
        raise AssertionError("RUST-080 rotation authorization payload mismatch")
    rows = auth.get("observers")
    if not isinstance(rows, list) or not (
        THRESHOLD <= len(rows) <= len(PREDECESSOR_PINNED_OBSERVERS)
    ):
        raise AssertionError("invalid RUST-080 rotation authorization size")
    if not all(
        isinstance(row, dict) and frozenset(row) == AUTH_OBSERVER_KEYS for row in rows
    ):
        raise AssertionError("invalid RUST-080 rotation authorization entry")
    ids = [row["observer_id"] for row in rows]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("RUST-080 rotation authorizer ids must be unique and sorted")
    if any(observer_id not in PREDECESSOR_PINNED_OBSERVERS for observer_id in ids):
        raise AssertionError("unknown RUST-080 rotation authorizer")
    message = rotation_message(rotation_raw)
    for row in rows:
        material_verify.ed25519_verify(
            PREDECESSOR_PINNED_OBSERVERS[row["observer_id"]],
            material_verify.decode_signature(row["signature"]),
            message,
        )


def validate_final_report(report: dict, set_sha: str) -> dict:
    if not isinstance(report, dict) or frozenset(report) != FINAL_REPORT_KEYS:
        raise AssertionError("invalid RUST-080 final observer report fields")
    if report.get("schema") != FINAL_REPORT_SCHEMA or report.get("algorithm") != ALGORITHM:
        raise AssertionError("invalid RUST-080 final observer report envelope")
    statement = report.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != FINAL_STATEMENT_KEYS:
        raise AssertionError("invalid RUST-080 final observer statement fields")
    if statement.get("schema") != FINAL_STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError("invalid RUST-080 final observer statement boundary")
    observer_id = statement.get("observer_id")
    if not isinstance(observer_id, str) or observer_id not in FINAL_PINNED_OBSERVERS:
        raise AssertionError("unknown RUST-080 final observer")
    if observer_id in CUMULATIVE_REVOKED_OBSERVER_IDS:
        raise AssertionError("revoked observer resurrected in RUST-080 final set")
    if (
        statement.get("observer_set_sequence") != FINAL_SET_SEQUENCE
        or statement.get("observer_set_sha256") != set_sha
    ):
        raise AssertionError("RUST-080 final observer-set epoch mismatch")
    material_verify.ed25519_verify(
        FINAL_PINNED_OBSERVERS[observer_id],
        material_verify.decode_signature(report["signature"]),
        final_message(statement),
    )
    return statement


def statement_matches_target(statement: dict, target: dict) -> bool:
    return all(statement.get(key) == target[key] for key in TARGET_KEYS)


def validate_final_bundle(bundle: dict, target: dict) -> None:
    set_sha = sha256(canonical(final_observer_set()))
    if (
        not isinstance(bundle, dict)
        or frozenset(bundle) != FINAL_BUNDLE_KEYS
        or bundle.get("schema") != FINAL_BUNDLE_SCHEMA
    ):
        raise AssertionError("invalid RUST-080 final observer bundle fields")
    if (
        bundle.get("observer_set_sequence") != FINAL_SET_SEQUENCE
        or bundle.get("observer_set_sha256") != set_sha
    ):
        raise AssertionError("RUST-080 final observer bundle set mismatch")
    if type(bundle.get("threshold")) is not int or bundle["threshold"] != THRESHOLD:
        raise AssertionError("invalid RUST-080 final observer threshold")
    if bundle.get("production") is not False:
        raise AssertionError("production final observation forbidden in RUST-080")
    reports = bundle.get("reports")
    if not isinstance(reports, list) or not (
        THRESHOLD <= len(reports) <= len(FINAL_PINNED_OBSERVERS)
    ):
        raise AssertionError("invalid RUST-080 final observer report count")
    statements = [validate_final_report(report, set_sha) for report in reports]
    ids = [statement["observer_id"] for statement in statements]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("RUST-080 final observer ids must be unique and sorted")
    for statement in statements:
        if statement["activation_source_commit"] != target["activation_source_commit"]:
            raise AssertionError("RUST-080 final observer source mismatch")
        same_parent = (
            statement["monitor_set_sequence"] == target["monitor_set_sequence"]
            and statement["previous_checkpoint_sha256"] == target["previous_checkpoint_sha256"]
        )
        exact = statement_matches_target(statement, target)
        if same_parent and not exact:
            raise AssertionError("observed RUST-080 final same-parent RUST-077 checkpoint fork")
        if not exact:
            raise AssertionError("RUST-080 final observer report does not match canonical checkpoint")


def verify(*args) -> None:
    if len(args) != 131:
        raise AssertionError("unexpected RUST-080 verifier argument count")
    *path_args, expected_source_sha, required_floor_text = args
    if len(path_args) != 129:
        raise AssertionError("unexpected RUST-080 path count")

    base_paths = path_args[:122]
    old_bundle_path, first_rotation_path, first_auth_path, first_successor_path = path_args[122:126]
    second_rotation_path, second_auth_path, final_bundle_path = path_args[126:129]

    rotation1_verify.verify(
        *base_paths,
        old_bundle_path, first_rotation_path, first_auth_path, first_successor_path,
        expected_source_sha, required_floor_text,
    )
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(
        base_paths[-1], "RUST-077 final monitor rotation checkpoint"
    )
    target = observer_verify.canonical_target(
        final_checkpoint_raw, final_checkpoint, expected_source_sha
    )

    first_rotation_raw, _ = floor_verify.load_canonical(
        first_rotation_path, "RUST-080 first observer rotation"
    )
    first_auth_raw, _ = floor_verify.load_canonical(
        first_auth_path, "RUST-080 first observer rotation authorization"
    )
    first_successor_raw, _ = floor_verify.load_canonical(
        first_successor_path, "RUST-080 first successor observer bundle"
    )
    second_rotation_raw, second_rotation = floor_verify.load_canonical(
        second_rotation_path, "RUST-080 second observer rotation"
    )
    _, second_auth = floor_verify.load_canonical(
        second_auth_path, "RUST-080 second rotation authorization"
    )
    _, final_bundle = floor_verify.load_canonical(
        final_bundle_path, "RUST-080 final observer bundle"
    )

    validate_rotation(
        second_rotation, target, first_rotation_raw, first_auth_raw, first_successor_raw
    )
    validate_rotation_auth(second_auth, second_rotation_raw)
    validate_final_bundle(final_bundle, target)
    ids = ",".join(
        report["statement"]["observer_id"] for report in final_bundle["reports"]
    )
    print(
        "RUST-080 multi-step RUST-077 checkpoint observer rotation: GREEN "
        f"source={expected_source_sha} sequence=2 "
        f"revoked={','.join(CUMULATIVE_REVOKED_OBSERVER_IDS)} final={ids}"
    )


def main() -> None:
    if len(sys.argv) != 133 or sys.argv[1] != "verify":
        raise SystemExit(
            "usage: rust_080_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_verify.py verify "
            "... FIRST_ROT AUTH SUCCESSOR SECOND_ROT AUTH FINAL_BUNDLE SOURCE_SHA REQUIRED_FLOOR"
        )
    paths = [Path(value) for value in sys.argv[2:-2]]
    verify(*paths, sys.argv[-2], sys.argv[-1])


if __name__ == "__main__":
    main()
