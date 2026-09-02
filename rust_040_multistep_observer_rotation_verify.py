#!/usr/bin/env python3
"""RUST-040: TEST-ONLY multi-step observer-set rotation continuity verifier."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_038_checkpoint_gossip_verify as gossip_verify
import rust_039_observer_set_rotation_verify as rotation1_verify

ROTATION_SCHEMA = "axven-native-checkpoint-observer-set-rotation-v2"
ROTATION_AUTH_SCHEMA = "axven-native-checkpoint-observer-set-rotation-quorum-v2"
ROTATION_PAYLOAD_TYPE = "application/vnd.axven.native-checkpoint-observer-set-rotation.v2+json"
FINAL_BUNDLE_SCHEMA = "axven-native-rotation-checkpoint-observation-bundle-v3"
FINAL_REPORT_SCHEMA = "axven-native-rotation-checkpoint-observation-v3"
FINAL_STATEMENT_SCHEMA = "axven-native-rotation-checkpoint-observation-statement-v3"
ROTATION_DOMAIN = b"AXVEN_NATIVE_CHECKPOINT_OBSERVER_SET_ROTATION_V2\x00"
FINAL_DOMAIN = b"AXVEN_NATIVE_ROTATION_CHECKPOINT_OBSERVATION_V3\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2
PREDECESSOR_SET_SEQUENCE = 1
FINAL_SET_SEQUENCE = 2
O5_ID = "rust-040-test-only-observer-5-v1"
O5_PUBLIC_KEY = bytes.fromhex("332ebe8d27cb7323b3a401c1c13b5dd64bccc0e10ecda1c2b5d11a03779a85e5")
CUMULATIVE_REVOKED_OBSERVER_IDS = [rotation1_verify.REVOKED_OBSERVER_ID, gossip_verify.OBSERVER_2_ID]
PREDECESSOR_PINNED_OBSERVERS = dict(rotation1_verify.NEW_PINNED_OBSERVERS)
FINAL_PINNED_OBSERVERS = {
    gossip_verify.OBSERVER_3_ID: gossip_verify.OBSERVER_3_PUBLIC_KEY,
    rotation1_verify.O4_ID: rotation1_verify.O4_PUBLIC_KEY,
    O5_ID: O5_PUBLIC_KEY,
}
ROTATION_KEYS = frozenset({
    "schema", "sequence", "from_set_sha256", "to_set", "cumulative_revoked_observer_ids",
    "predecessor_rotation_sha256", "predecessor_successor_bundle_sha256",
    "checkpoint_statement_sha256", "activation_source_commit", "production",
})
AUTH_KEYS = frozenset({
    "schema", "algorithm", "threshold", "payload_type", "payload_sha256", "observers", "production",
})
AUTH_OBSERVER_KEYS = frozenset({"observer_id", "signature"})
FINAL_BUNDLE_KEYS = frozenset({
    "schema", "observer_set_sequence", "observer_set_sha256", "threshold", "reports", "production",
})
FINAL_REPORT_KEYS = frozenset({"schema", "algorithm", "statement", "signature"})
FINAL_STATEMENT_KEYS = frozenset({
    "schema", "observer_id", "observer_set_sequence", "observer_set_sha256",
    "checkpoint_statement_sha256", "set_sequence", "set_sha256", "journal_sha256",
    "head_entry_sha256", "previous_checkpoint_sha256", "activation_source_commit", "production",
})


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


def validate_rotation(rotation: dict, target: dict, first_rotation_raw: bytes, first_successor_raw: bytes, source_sha: str) -> None:
    if frozenset(rotation) != ROTATION_KEYS or rotation.get("schema") != ROTATION_SCHEMA:
        raise AssertionError("invalid second observer-set rotation fields")
    if type(rotation.get("sequence")) is not int or rotation["sequence"] != FINAL_SET_SEQUENCE:
        raise AssertionError("invalid second observer-set rotation sequence")
    if rotation.get("from_set_sha256") != sha256(canonical(rotation1_verify.new_observer_set())):
        raise AssertionError("second observer-set predecessor mismatch")
    if rotation.get("to_set") != final_observer_set():
        raise AssertionError("unexpected final observer set")
    if rotation.get("cumulative_revoked_observer_ids") != CUMULATIVE_REVOKED_OBSERVER_IDS:
        raise AssertionError("cumulative observer revocation continuity mismatch")
    if rotation.get("predecessor_rotation_sha256") != sha256(first_rotation_raw):
        raise AssertionError("predecessor observer rotation digest mismatch")
    if rotation.get("predecessor_successor_bundle_sha256") != sha256(first_successor_raw):
        raise AssertionError("predecessor observer bundle digest mismatch")
    if rotation.get("checkpoint_statement_sha256") != target["checkpoint_statement_sha256"]:
        raise AssertionError("second rotation checkpoint binding mismatch")
    if rotation.get("activation_source_commit") != source_sha:
        raise AssertionError("second observer rotation source mismatch")
    if rotation.get("production") is not False:
        raise AssertionError("production second observer-set rotation forbidden in RUST-040")


def validate_rotation_auth(auth: dict, rotation_raw: bytes) -> None:
    if frozenset(auth) != AUTH_KEYS or auth.get("schema") != ROTATION_AUTH_SCHEMA:
        raise AssertionError("invalid second observer rotation authorization fields")
    if auth.get("algorithm") != ALGORITHM or auth.get("payload_type") != ROTATION_PAYLOAD_TYPE:
        raise AssertionError("invalid second observer rotation authorization envelope")
    if type(auth.get("threshold")) is not int or auth["threshold"] != THRESHOLD:
        raise AssertionError("invalid second observer rotation authorization threshold")
    if auth.get("payload_sha256") != sha256(rotation_raw) or auth.get("production") is not False:
        raise AssertionError("second observer rotation authorization payload mismatch")
    observers = auth.get("observers")
    if not isinstance(observers, list) or not (THRESHOLD <= len(observers) <= len(PREDECESSOR_PINNED_OBSERVERS)):
        raise AssertionError("invalid second observer rotation authorization size")
    if not all(isinstance(item, dict) and frozenset(item) == AUTH_OBSERVER_KEYS for item in observers):
        raise AssertionError("invalid second observer rotation authorization entry")
    ids = [item["observer_id"] for item in observers]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("second rotation authorizer ids must be unique and sorted")
    if any(observer_id not in PREDECESSOR_PINNED_OBSERVERS for observer_id in ids):
        raise AssertionError("unknown second rotation authorizer")
    message = rotation_message(rotation_raw)
    for item in observers:
        material_verify.ed25519_verify(
            PREDECESSOR_PINNED_OBSERVERS[item["observer_id"]],
            material_verify.decode_signature(item["signature"]),
            message,
        )


def validate_final_report(report: dict, target: dict, set_sha: str) -> dict:
    if not isinstance(report, dict) or frozenset(report) != FINAL_REPORT_KEYS:
        raise AssertionError("invalid final observer report fields")
    if report.get("schema") != FINAL_REPORT_SCHEMA or report.get("algorithm") != ALGORITHM:
        raise AssertionError("invalid final observer report envelope")
    statement = report.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != FINAL_STATEMENT_KEYS:
        raise AssertionError("invalid final observer statement fields")
    if statement.get("schema") != FINAL_STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError("invalid final observer statement boundary")
    observer_id = statement.get("observer_id")
    if not isinstance(observer_id, str) or observer_id not in FINAL_PINNED_OBSERVERS:
        raise AssertionError("unknown final observer")
    if observer_id in CUMULATIVE_REVOKED_OBSERVER_IDS:
        raise AssertionError("revoked observer resurrected in final observer set")
    if statement.get("observer_set_sequence") != FINAL_SET_SEQUENCE or statement.get("observer_set_sha256") != set_sha:
        raise AssertionError("final observer-set epoch mismatch")
    material_verify.ed25519_verify(
        FINAL_PINNED_OBSERVERS[observer_id],
        material_verify.decode_signature(report["signature"]),
        final_message(statement),
    )
    return statement


def validate_final_bundle(bundle: dict, target: dict) -> None:
    set_sha = sha256(canonical(final_observer_set()))
    if frozenset(bundle) != FINAL_BUNDLE_KEYS or bundle.get("schema") != FINAL_BUNDLE_SCHEMA:
        raise AssertionError("invalid final observation bundle fields")
    if bundle.get("observer_set_sequence") != FINAL_SET_SEQUENCE or bundle.get("observer_set_sha256") != set_sha:
        raise AssertionError("final observation bundle set mismatch")
    if type(bundle.get("threshold")) is not int or bundle["threshold"] != THRESHOLD:
        raise AssertionError("invalid final observation threshold")
    if bundle.get("production") is not False:
        raise AssertionError("production final observation forbidden in RUST-040")
    reports = bundle.get("reports")
    if not isinstance(reports, list) or not (THRESHOLD <= len(reports) <= len(FINAL_PINNED_OBSERVERS)):
        raise AssertionError("invalid final observation report count")
    statements = [validate_final_report(report, target, set_sha) for report in reports]
    ids = [statement["observer_id"] for statement in statements]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("final observer ids must be unique and sorted")
    matching = 0
    for statement in statements:
        if statement["activation_source_commit"] != target["activation_source_commit"]:
            raise AssertionError("final observer source mismatch")
        same_epoch_parent = (
            statement["set_sequence"] == target["set_sequence"]
            and statement["previous_checkpoint_sha256"] == target["previous_checkpoint_sha256"]
        )
        exact = all(statement[key] == target[key] for key in target)
        if same_epoch_parent and not exact:
            raise AssertionError("observed final same-parent checkpoint fork")
        if not exact:
            raise AssertionError("final observer report does not match canonical checkpoint")
        matching += 1
    if matching < THRESHOLD:
        raise AssertionError("final observer quorum below threshold")


def verify(
    final_state_path: Path,
    external_floor_path: Path,
    first_witness_rotation_path: Path,
    first_witness_auth_path: Path,
    first_witness_quorum_path: Path,
    second_witness_rotation_path: Path,
    second_witness_auth_path: Path,
    final_witness_quorum_path: Path,
    prefix_journal_path: Path,
    prefix_checkpoint_path: Path,
    final_journal_path: Path,
    final_checkpoint_path: Path,
    old_observer_bundle_path: Path,
    first_observer_rotation_path: Path,
    first_observer_auth_path: Path,
    first_observer_successor_path: Path,
    second_observer_rotation_path: Path,
    second_observer_auth_path: Path,
    final_observer_bundle_path: Path,
    expected_source_sha: str,
    required_floor_text: str,
) -> None:
    rotation1_verify.verify(
        final_state_path, external_floor_path, first_witness_rotation_path, first_witness_auth_path,
        first_witness_quorum_path, second_witness_rotation_path, second_witness_auth_path,
        final_witness_quorum_path, prefix_journal_path, prefix_checkpoint_path, final_journal_path,
        final_checkpoint_path, old_observer_bundle_path, first_observer_rotation_path,
        first_observer_auth_path, first_observer_successor_path, expected_source_sha, required_floor_text,
    )
    _, checkpoint = floor_verify.load_canonical(final_checkpoint_path, "final checkpoint")
    target = gossip_verify.canonical_target(checkpoint, expected_source_sha)
    first_rotation_raw, _ = floor_verify.load_canonical(first_observer_rotation_path, "first observer rotation")
    first_successor_raw, _ = floor_verify.load_canonical(first_observer_successor_path, "first observer successor")
    second_rotation_raw, second_rotation = floor_verify.load_canonical(second_observer_rotation_path, "second observer rotation")
    _, second_auth = floor_verify.load_canonical(second_observer_auth_path, "second observer rotation authorization")
    _, final_bundle = floor_verify.load_canonical(final_observer_bundle_path, "final observer bundle")
    validate_rotation(second_rotation, target, first_rotation_raw, first_successor_raw, expected_source_sha)
    validate_rotation_auth(second_auth, second_rotation_raw)
    validate_final_bundle(final_bundle, target)
    ids = ",".join(report["statement"]["observer_id"] for report in final_bundle["reports"])
    print(
        "RUST-040 multi-step observer-set rotation: GREEN "
        f"source={expected_source_sha} sequence=2 revoked={','.join(CUMULATIVE_REVOKED_OBSERVER_IDS)} final={ids}"
    )


def main() -> None:
    if len(sys.argv) != 23 or sys.argv[1] != "verify":
        raise SystemExit("usage: rust_040_multistep_observer_rotation_verify.py verify ... FIRST_ROTATION FIRST_AUTH FIRST_SUCCESSOR SECOND_ROTATION SECOND_AUTH FINAL_BUNDLE SOURCE_SHA REQUIRED_FLOOR")
    paths = [Path(value) for value in sys.argv[2:-2]]
    verify(*paths, sys.argv[-2], sys.argv[-1])


if __name__ == "__main__":
    main()
