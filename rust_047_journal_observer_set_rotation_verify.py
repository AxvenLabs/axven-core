#!/usr/bin/env python3
"""RUST-047: TEST-ONLY monitor-journal observer-set rotation verifier."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_046_monitor_journal_gossip_verify as gossip_verify

OBSERVER_SET_SCHEMA = "axven-native-monitor-journal-observer-set-v1"
ROTATION_SCHEMA = "axven-native-monitor-journal-observer-set-rotation-v1"
ROTATION_AUTH_SCHEMA = "axven-native-monitor-journal-observer-set-rotation-quorum-v1"
ROTATION_PAYLOAD_TYPE = "application/vnd.axven.native-monitor-journal-observer-set-rotation.v1+json"
SUCCESSOR_BUNDLE_SCHEMA = "axven-native-monitor-rotation-journal-checkpoint-observation-bundle-v2"
SUCCESSOR_REPORT_SCHEMA = "axven-native-monitor-rotation-journal-checkpoint-observation-v2"
SUCCESSOR_STATEMENT_SCHEMA = "axven-native-monitor-rotation-journal-checkpoint-observation-statement-v2"
ROTATION_DOMAIN = b"AXVEN_NATIVE_MONITOR_JOURNAL_OBSERVER_SET_ROTATION_V1\x00"
SUCCESSOR_DOMAIN = b"AXVEN_NATIVE_MONITOR_ROTATION_JOURNAL_CHECKPOINT_OBSERVATION_V2\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2
OLD_SET_SEQUENCE = 0
NEW_SET_SEQUENCE = 1
J4_ID = "rust-047-test-only-journal-observer-4-v1"
J4_PUBLIC_KEY = bytes.fromhex("3f0dda81e6abbcc5f17c359df8517177769d2dfff3d4ce942e7ce9a82dfb0db2")
REVOKED_OBSERVER_ID = gossip_verify.OBSERVER_1_ID
OLD_PINNED_OBSERVERS = dict(gossip_verify.PINNED_OBSERVERS)
NEW_PINNED_OBSERVERS = {
    gossip_verify.OBSERVER_2_ID: gossip_verify.OBSERVER_2_PUBLIC_KEY,
    gossip_verify.OBSERVER_3_ID: gossip_verify.OBSERVER_3_PUBLIC_KEY,
    J4_ID: J4_PUBLIC_KEY,
}
SET_KEYS = frozenset({"schema", "sequence", "threshold", "observers", "production"})
SET_OBSERVER_KEYS = frozenset({"observer_id", "public_key"})
ROTATION_KEYS = frozenset({
    "schema", "sequence", "from_set_sha256", "to_set", "revoked_observer_ids",
    "predecessor_observation_bundle_sha256", "checkpoint_sha256",
    "checkpoint_statement_sha256", "activation_source_commit", "production",
})
AUTH_KEYS = frozenset({
    "schema", "algorithm", "threshold", "payload_type", "payload_sha256",
    "observers", "production",
})
AUTH_OBSERVER_KEYS = frozenset({"observer_id", "signature"})
SUCCESSOR_BUNDLE_KEYS = frozenset({
    "schema", "observer_set_sequence", "observer_set_sha256", "threshold", "reports", "production",
})
SUCCESSOR_REPORT_KEYS = frozenset({"schema", "algorithm", "statement", "signature"})
SUCCESSOR_STATEMENT_KEYS = frozenset({
    "schema", "observer_id", "observer_set_sequence", "observer_set_sha256",
    "checkpoint_sha256", "checkpoint_statement_sha256", "monitor_set_sequence",
    "monitor_set_sha256", "journal_sha256", "head_entry_sha256",
    "previous_checkpoint_sha256", "observer_checkpoint_sha256",
    "activation_source_commit", "production",
})


def canonical(value: dict) -> bytes:
    return material_verify.canonical(value)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def observer_set(sequence: int, pins: dict[str, bytes]) -> dict:
    return {
        "schema": OBSERVER_SET_SCHEMA,
        "sequence": sequence,
        "threshold": THRESHOLD,
        "observers": [
            {"observer_id": observer_id, "public_key": pins[observer_id].hex()}
            for observer_id in sorted(pins)
        ],
        "production": False,
    }


def old_observer_set() -> dict:
    return observer_set(OLD_SET_SEQUENCE, OLD_PINNED_OBSERVERS)


def new_observer_set() -> dict:
    return observer_set(NEW_SET_SEQUENCE, NEW_PINNED_OBSERVERS)


def rotation_message(rotation_raw: bytes) -> bytes:
    return ROTATION_DOMAIN + len(rotation_raw).to_bytes(8, "big") + rotation_raw


def successor_message(statement: dict) -> bytes:
    raw = canonical(statement)
    return SUCCESSOR_DOMAIN + len(raw).to_bytes(8, "big") + raw


def validate_rotation(rotation: dict, old_bundle_raw: bytes, target: dict, source_sha: str) -> None:
    if not isinstance(rotation, dict) or frozenset(rotation) != ROTATION_KEYS or rotation.get("schema") != ROTATION_SCHEMA:
        raise AssertionError("invalid journal-observer rotation fields")
    if type(rotation.get("sequence")) is not int or rotation["sequence"] != NEW_SET_SEQUENCE:
        raise AssertionError("invalid journal-observer rotation sequence")
    if rotation.get("from_set_sha256") != sha256(canonical(old_observer_set())):
        raise AssertionError("journal-observer predecessor set mismatch")
    if rotation.get("to_set") != new_observer_set():
        raise AssertionError("unexpected successor journal-observer set")
    if rotation.get("revoked_observer_ids") != [REVOKED_OBSERVER_ID]:
        raise AssertionError("journal-observer revocation continuity mismatch")
    if rotation.get("predecessor_observation_bundle_sha256") != sha256(old_bundle_raw):
        raise AssertionError("predecessor observation bundle mismatch")
    if rotation.get("checkpoint_sha256") != target["checkpoint_sha256"]:
        raise AssertionError("rotation checkpoint binding mismatch")
    if rotation.get("checkpoint_statement_sha256") != target["checkpoint_statement_sha256"]:
        raise AssertionError("rotation checkpoint-statement binding mismatch")
    if rotation.get("activation_source_commit") != source_sha:
        raise AssertionError("rotation source mismatch")
    if rotation.get("production") is not False:
        raise AssertionError("production journal-observer rotation forbidden in RUST-047")


def validate_rotation_auth(auth: dict, rotation_raw: bytes) -> None:
    if not isinstance(auth, dict) or frozenset(auth) != AUTH_KEYS or auth.get("schema") != ROTATION_AUTH_SCHEMA:
        raise AssertionError("invalid journal-observer rotation authorization fields")
    if auth.get("algorithm") != ALGORITHM or auth.get("payload_type") != ROTATION_PAYLOAD_TYPE:
        raise AssertionError("invalid journal-observer rotation authorization envelope")
    if type(auth.get("threshold")) is not int or auth["threshold"] != THRESHOLD:
        raise AssertionError("invalid journal-observer rotation authorization threshold")
    if auth.get("payload_sha256") != sha256(rotation_raw) or auth.get("production") is not False:
        raise AssertionError("journal-observer rotation authorization payload mismatch")
    observers = auth.get("observers")
    if not isinstance(observers, list) or not (THRESHOLD <= len(observers) <= len(OLD_PINNED_OBSERVERS)):
        raise AssertionError("invalid journal-observer rotation authorization size")
    if not all(isinstance(item, dict) and frozenset(item) == AUTH_OBSERVER_KEYS for item in observers):
        raise AssertionError("invalid journal-observer rotation authorization entry")
    ids = [item["observer_id"] for item in observers]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("rotation authorizer ids must be unique and sorted")
    if any(observer_id not in OLD_PINNED_OBSERVERS for observer_id in ids):
        raise AssertionError("unknown journal-observer rotation authorizer")
    message = rotation_message(rotation_raw)
    for item in observers:
        material_verify.ed25519_verify(
            OLD_PINNED_OBSERVERS[item["observer_id"]],
            material_verify.decode_signature(item["signature"]),
            message,
        )


def validate_successor_report(report: dict, set_sha: str) -> dict:
    if not isinstance(report, dict) or frozenset(report) != SUCCESSOR_REPORT_KEYS:
        raise AssertionError("invalid successor journal-observer report fields")
    if report.get("schema") != SUCCESSOR_REPORT_SCHEMA or report.get("algorithm") != ALGORITHM:
        raise AssertionError("invalid successor journal-observer report envelope")
    statement = report.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != SUCCESSOR_STATEMENT_KEYS:
        raise AssertionError("invalid successor journal-observer statement fields")
    if statement.get("schema") != SUCCESSOR_STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError("invalid successor journal-observer statement boundary")
    observer_id = statement.get("observer_id")
    if not isinstance(observer_id, str) or observer_id not in NEW_PINNED_OBSERVERS:
        raise AssertionError("unknown successor journal observer")
    if observer_id == REVOKED_OBSERVER_ID:
        raise AssertionError("revoked journal observer resurrected")
    if statement.get("observer_set_sequence") != NEW_SET_SEQUENCE or statement.get("observer_set_sha256") != set_sha:
        raise AssertionError("successor journal-observer set epoch mismatch")
    material_verify.ed25519_verify(
        NEW_PINNED_OBSERVERS[observer_id],
        material_verify.decode_signature(report["signature"]),
        successor_message(statement),
    )
    return statement


def validate_successor_bundle(bundle: dict, target: dict) -> None:
    set_sha = sha256(canonical(new_observer_set()))
    if not isinstance(bundle, dict) or frozenset(bundle) != SUCCESSOR_BUNDLE_KEYS or bundle.get("schema") != SUCCESSOR_BUNDLE_SCHEMA:
        raise AssertionError("invalid successor journal-observation bundle fields")
    if bundle.get("observer_set_sequence") != NEW_SET_SEQUENCE or bundle.get("observer_set_sha256") != set_sha:
        raise AssertionError("successor journal-observation bundle set mismatch")
    if type(bundle.get("threshold")) is not int or bundle["threshold"] != THRESHOLD:
        raise AssertionError("invalid successor journal-observation threshold")
    if bundle.get("production") is not False:
        raise AssertionError("production successor journal observation forbidden in RUST-047")
    reports = bundle.get("reports")
    if not isinstance(reports, list) or not (THRESHOLD <= len(reports) <= len(NEW_PINNED_OBSERVERS)):
        raise AssertionError("invalid successor journal-observation report count")
    statements = [validate_successor_report(report, set_sha) for report in reports]
    ids = [statement["observer_id"] for statement in statements]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("successor journal-observer ids must be unique and sorted")
    matching = 0
    for statement in statements:
        if statement["activation_source_commit"] != target["activation_source_commit"]:
            raise AssertionError("successor journal-observer source mismatch")
        same_epoch_parent = (
            statement["monitor_set_sequence"] == target["monitor_set_sequence"]
            and statement["previous_checkpoint_sha256"] == target["previous_checkpoint_sha256"]
        )
        exact = all(statement[key] == target[key] for key in target)
        if same_epoch_parent and not exact:
            raise AssertionError("observed successor same-parent monitor-journal checkpoint fork")
        if not exact:
            raise AssertionError("successor journal-observer report does not match canonical checkpoint")
        matching += 1
    if matching < THRESHOLD:
        raise AssertionError("successor journal-observer quorum below threshold")


def verify(*args) -> None:
    if len(args) != 40:
        raise AssertionError("unexpected RUST-047 verifier argument count")
    *base_paths, old_bundle_path, rotation_path, auth_path, successor_path, expected_source_sha, required_floor_text = args
    if len(base_paths) != 34:
        raise AssertionError("unexpected RUST-047 base path count")
    gossip_verify.verify(*base_paths, old_bundle_path, expected_source_sha, required_floor_text)

    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(base_paths[-1], "final monitor checkpoint")
    target = gossip_verify.canonical_target(final_checkpoint_raw, final_checkpoint, expected_source_sha)
    old_bundle_raw, _ = floor_verify.load_canonical(old_bundle_path, "predecessor journal-observer bundle")
    rotation_raw, rotation = floor_verify.load_canonical(rotation_path, "journal-observer rotation")
    _, auth = floor_verify.load_canonical(auth_path, "journal-observer rotation authorization")
    _, successor = floor_verify.load_canonical(successor_path, "successor journal-observer bundle")
    validate_rotation(rotation, old_bundle_raw, target, expected_source_sha)
    validate_rotation_auth(auth, rotation_raw)
    validate_successor_bundle(successor, target)
    ids = ",".join(report["statement"]["observer_id"] for report in successor["reports"])
    print(
        "RUST-047 journal-observer set rotation: GREEN "
        f"source={expected_source_sha} revoked={REVOKED_OBSERVER_ID} successor={ids}"
    )


def main() -> None:
    if len(sys.argv) != 42 or sys.argv[1] != "verify":
        raise SystemExit(
            "usage: rust_047_journal_observer_set_rotation_verify.py verify "
            "... OLD_BUNDLE ROTATION AUTH SUCCESSOR SOURCE_SHA REQUIRED_FLOOR"
        )
    paths = [Path(value) for value in sys.argv[2:-2]]
    verify(*paths, sys.argv[-2], sys.argv[-1])


if __name__ == "__main__":
    main()
