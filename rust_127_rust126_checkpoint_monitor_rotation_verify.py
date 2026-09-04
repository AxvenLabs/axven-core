#!/usr/bin/env python3
"""RUST-127: TEST-ONLY monitor-set rotation for RUST-126 checkpoint monitors."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_126_rust125_checkpoint_monitor_verify as monitor_verify

MONITOR_SET_SCHEMA = "axven-native-rust127-monitor-set-v1"
ROTATION_SCHEMA = "axven-native-rust127-monitor-set-rotation-v1"
ROTATION_AUTH_SCHEMA = "axven-native-rust127-monitor-set-rotation-quorum-v1"
ROTATION_PAYLOAD_TYPE = "application/vnd.axven.native-rust127-monitor-set-rotation.v1+json"
SUCCESSOR_BUNDLE_SCHEMA = "axven-native-rust127-checkpoint-monitor-bundle-v2"
SUCCESSOR_REPORT_SCHEMA = "axven-native-rust127-checkpoint-monitor-report-v2"
SUCCESSOR_STATEMENT_SCHEMA = "axven-native-rust127-checkpoint-monitor-statement-v2"
ROTATION_DOMAIN = b"AXVEN_NATIVE_RUST103_MONITOR_SET_ROTATION_V1\x00"
SUCCESSOR_DOMAIN = b"AXVEN_NATIVE_RUST103_CHECKPOINT_MONITOR_V2\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2
OLD_SET_SEQUENCE = 0
NEW_SET_SEQUENCE = 1

M4_ID = "rust-127-test-only-monitor-rotation-journal-monitor-4-v1"
M4_PUBLIC_KEY = bytes.fromhex("e63cc9f1bfea63e045538d59abdabe2c1aee0557daf2894bf3115d177d16506c")
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
    "predecessor_monitor_bundle_sha256", *monitor_verify.TARGET_KEYS, "production",
})
AUTH_KEYS = frozenset({
    "schema", "algorithm", "threshold", "payload_type", "payload_sha256",
    "monitors", "production",
})
AUTH_MONITOR_KEYS = frozenset({"monitor_id", "signature"})
SUCCESSOR_BUNDLE_KEYS = frozenset({
    "schema", "monitor_set_sequence", "monitor_set_sha256", "threshold",
    "reports", "production",
})
SUCCESSOR_REPORT_KEYS = frozenset({"schema", "algorithm", "statement", "signature"})
SUCCESSOR_STATEMENT_KEYS = frozenset({
    "schema", "monitor_id", "successor_monitor_set_sequence", "successor_monitor_set_sha256",
    *monitor_verify.TARGET_KEYS, "production",
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


def validate_rotation(rotation: dict, old_bundle_raw: bytes, target: dict) -> None:
    if (
        not isinstance(rotation, dict)
        or frozenset(rotation) != ROTATION_KEYS
        or rotation.get("schema") != ROTATION_SCHEMA
    ):
        raise AssertionError("invalid RUST-127 monitor rotation fields")
    if type(rotation.get("sequence")) is not int or rotation["sequence"] != NEW_SET_SEQUENCE:
        raise AssertionError("invalid RUST-127 monitor rotation sequence")
    if rotation.get("from_set_sha256") != sha256(canonical(old_monitor_set())):
        raise AssertionError("RUST-127 predecessor monitor set mismatch")
    if rotation.get("to_set") != new_monitor_set():
        raise AssertionError("unexpected RUST-127 successor monitor set")
    if rotation.get("revoked_monitor_ids") != [REVOKED_MONITOR_ID]:
        raise AssertionError("RUST-127 monitor revocation continuity mismatch")
    if rotation.get("predecessor_monitor_bundle_sha256") != sha256(old_bundle_raw):
        raise AssertionError("RUST-127 predecessor monitor bundle mismatch")
    for key in monitor_verify.TARGET_KEYS:
        if rotation.get(key) != target[key]:
            raise AssertionError(f"RUST-127 rotation target binding mismatch: {key}")
    if rotation.get("production") is not False:
        raise AssertionError("production monitor rotation forbidden in RUST-127")


def validate_rotation_auth(auth: dict, rotation_raw: bytes) -> None:
    if (
        not isinstance(auth, dict)
        or frozenset(auth) != AUTH_KEYS
        or auth.get("schema") != ROTATION_AUTH_SCHEMA
    ):
        raise AssertionError("invalid RUST-127 rotation authorization fields")
    if auth.get("algorithm") != ALGORITHM or auth.get("payload_type") != ROTATION_PAYLOAD_TYPE:
        raise AssertionError("invalid RUST-127 rotation authorization envelope")
    if type(auth.get("threshold")) is not int or auth["threshold"] != THRESHOLD:
        raise AssertionError("invalid RUST-127 rotation authorization threshold")
    if auth.get("payload_sha256") != sha256(rotation_raw) or auth.get("production") is not False:
        raise AssertionError("RUST-127 rotation authorization payload mismatch")
    monitors = auth.get("monitors")
    if not isinstance(monitors, list) or not (THRESHOLD <= len(monitors) <= len(OLD_PINNED_MONITORS)):
        raise AssertionError("invalid RUST-127 rotation authorization size")
    if not all(isinstance(item, dict) and frozenset(item) == AUTH_MONITOR_KEYS for item in monitors):
        raise AssertionError("invalid RUST-127 rotation authorization entry")
    ids = [item["monitor_id"] for item in monitors]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("RUST-127 rotation authorizer ids must be unique and sorted")
    if any(monitor_id not in OLD_PINNED_MONITORS for monitor_id in ids):
        raise AssertionError("unknown RUST-127 rotation authorizer")
    message = rotation_message(rotation_raw)
    for item in monitors:
        material_verify.ed25519_verify(
            OLD_PINNED_MONITORS[item["monitor_id"]],
            material_verify.decode_signature(item["signature"]),
            message,
        )


def validate_successor_report(report: dict, set_sha: str) -> dict:
    if not isinstance(report, dict) or frozenset(report) != SUCCESSOR_REPORT_KEYS:
        raise AssertionError("invalid RUST-127 successor monitor report fields")
    if report.get("schema") != SUCCESSOR_REPORT_SCHEMA or report.get("algorithm") != ALGORITHM:
        raise AssertionError("invalid RUST-127 successor monitor report envelope")
    statement = report.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != SUCCESSOR_STATEMENT_KEYS:
        raise AssertionError("invalid RUST-127 successor monitor statement fields")
    if statement.get("schema") != SUCCESSOR_STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError("invalid RUST-127 successor monitor statement boundary")
    monitor_id = statement.get("monitor_id")
    if not isinstance(monitor_id, str) or monitor_id not in NEW_PINNED_MONITORS:
        raise AssertionError("unknown RUST-127 successor monitor")
    if monitor_id == REVOKED_MONITOR_ID:
        raise AssertionError("revoked RUST-127 monitor resurrected")
    if (
        statement.get("successor_monitor_set_sequence") != NEW_SET_SEQUENCE
        or statement.get("successor_monitor_set_sha256") != set_sha
    ):
        raise AssertionError("RUST-127 successor monitor-set epoch mismatch")
    material_verify.ed25519_verify(
        NEW_PINNED_MONITORS[monitor_id],
        material_verify.decode_signature(report["signature"]),
        successor_message(statement),
    )
    return statement


def validate_successor_bundle(bundle: dict, target: dict) -> None:
    set_sha = sha256(canonical(new_monitor_set()))
    if (
        not isinstance(bundle, dict)
        or frozenset(bundle) != SUCCESSOR_BUNDLE_KEYS
        or bundle.get("schema") != SUCCESSOR_BUNDLE_SCHEMA
    ):
        raise AssertionError("invalid RUST-127 successor monitor bundle fields")
    if bundle.get("monitor_set_sequence") != NEW_SET_SEQUENCE or bundle.get("monitor_set_sha256") != set_sha:
        raise AssertionError("RUST-127 successor monitor bundle set mismatch")
    if type(bundle.get("threshold")) is not int or bundle["threshold"] != THRESHOLD:
        raise AssertionError("invalid RUST-127 successor monitor threshold")
    if bundle.get("production") is not False:
        raise AssertionError("production successor monitoring forbidden in RUST-127")
    reports = bundle.get("reports")
    if not isinstance(reports, list) or not (THRESHOLD <= len(reports) <= len(NEW_PINNED_MONITORS)):
        raise AssertionError("invalid RUST-127 successor monitor report count")
    statements = [validate_successor_report(report, set_sha) for report in reports]
    ids = [statement["monitor_id"] for statement in statements]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("RUST-127 successor monitor ids must be unique and sorted")
    for statement in statements:
        if statement["activation_source_commit"] != target["activation_source_commit"]:
            raise AssertionError("RUST-127 successor monitor source mismatch")
        same_parent = (
            statement["monitor_set_sequence"] == target["monitor_set_sequence"]
            and statement["previous_checkpoint_sha256"] == target["previous_checkpoint_sha256"]
        )
        exact = all(statement[key] == target[key] for key in monitor_verify.TARGET_KEYS)
        if same_parent and not exact:
            raise AssertionError("observed RUST-127 successor same-parent checkpoint fork")
        if not exact:
            raise AssertionError("RUST-127 successor monitor report does not match canonical checkpoint")


def verify(*args) -> None:
    if len(args) != 260:
        raise AssertionError("unexpected RUST-127 verifier argument count")
    *base_paths, old_bundle_path, rotation_path, auth_path, successor_path, expected_source_sha, required_floor_text = args
    if len(base_paths) != 254:
        raise AssertionError("unexpected RUST-127 base path count")

    monitor_verify.verify(*base_paths, old_bundle_path, expected_source_sha, required_floor_text)
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(
        base_paths[253], "RUST-125 final monitor rotation checkpoint"
    )
    target = monitor_verify.checkpoint_target(final_checkpoint_raw, final_checkpoint["statement"])
    if target["activation_source_commit"] != expected_source_sha:
        raise AssertionError("RUST-127 checkpoint source mismatch")

    old_bundle_raw, _ = floor_verify.load_canonical(old_bundle_path, "RUST-127 predecessor monitor bundle")
    rotation_raw, rotation = floor_verify.load_canonical(rotation_path, "RUST-127 monitor-set rotation")
    _, auth = floor_verify.load_canonical(auth_path, "RUST-127 monitor-set rotation authorization")
    _, successor = floor_verify.load_canonical(successor_path, "RUST-127 successor monitor bundle")
    validate_rotation(rotation, old_bundle_raw, target)
    validate_rotation_auth(auth, rotation_raw)
    validate_successor_bundle(successor, target)
    ids = ",".join(report["statement"]["monitor_id"] for report in successor["reports"])
    print(
        "RUST-127 RUST-125 journal checkpoint monitor-set rotation: GREEN "
        f"source={expected_source_sha} revoked={REVOKED_MONITOR_ID} successor={ids}"
    )


def main() -> None:
    if len(sys.argv) != 262 or sys.argv[1] != "verify":
        raise SystemExit(
            "usage: rust_127_rust126_checkpoint_monitor_rotation_verify.py verify "
            "... OLD_BUNDLE ROTATION AUTH SUCCESSOR SOURCE_SHA REQUIRED_FLOOR"
        )
    paths = [Path(value) for value in sys.argv[2:-2]]
    verify(*paths, sys.argv[-2], sys.argv[-1])


if __name__ == "__main__":
    main()
