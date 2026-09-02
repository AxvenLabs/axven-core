#!/usr/bin/env python3
"""RUST-038: TEST-ONLY multi-observer checkpoint gossip verifier."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_037_rotation_journal_verify as journal_verify

BUNDLE_SCHEMA = "axven-native-rotation-checkpoint-observation-bundle-v1"
REPORT_SCHEMA = "axven-native-rotation-checkpoint-observation-v1"
STATEMENT_SCHEMA = "axven-native-rotation-checkpoint-observation-statement-v1"
OBSERVATION_DOMAIN = b"AXVEN_NATIVE_ROTATION_CHECKPOINT_OBSERVATION_V1\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2
OBSERVER_1_ID = "rust-038-test-only-observer-1-v1"
OBSERVER_2_ID = "rust-038-test-only-observer-2-v1"
OBSERVER_3_ID = "rust-038-test-only-observer-3-v1"
OBSERVER_1_PUBLIC_KEY = bytes.fromhex("c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242")
OBSERVER_2_PUBLIC_KEY = bytes.fromhex("34b4d9043156cb6dcf0beb0a2949b7559c940d2bcb6dbe8c53a9b30278e3a746")
OBSERVER_3_PUBLIC_KEY = bytes.fromhex("c853ad0f0cd2b619aea92ceec4fd56a24d6499d584ce79257e45cfd8139b60a7")
PINNED_OBSERVERS = {
    OBSERVER_1_ID: OBSERVER_1_PUBLIC_KEY,
    OBSERVER_2_ID: OBSERVER_2_PUBLIC_KEY,
    OBSERVER_3_ID: OBSERVER_3_PUBLIC_KEY,
}
BUNDLE_KEYS = frozenset({"schema", "threshold", "reports", "production"})
REPORT_KEYS = frozenset({"schema", "algorithm", "statement", "signature"})
STATEMENT_KEYS = frozenset({
    "schema", "observer_id", "checkpoint_statement_sha256", "set_sequence",
    "set_sha256", "journal_sha256", "head_entry_sha256",
    "previous_checkpoint_sha256", "activation_source_commit", "production",
})


def canonical(value: dict) -> bytes:
    return material_verify.canonical(value)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def observation_message(statement: dict) -> bytes:
    raw = canonical(statement)
    return OBSERVATION_DOMAIN + len(raw).to_bytes(8, "big") + raw


def canonical_target(final_checkpoint: dict, source_sha: str) -> dict:
    statement = final_checkpoint.get("statement")
    if not isinstance(statement, dict):
        raise AssertionError("missing final checkpoint statement")
    return {
        "checkpoint_statement_sha256": sha256(canonical(statement)),
        "set_sequence": statement["set_sequence"],
        "set_sha256": statement["set_sha256"],
        "journal_sha256": statement["journal_sha256"],
        "head_entry_sha256": statement["head_entry_sha256"],
        "previous_checkpoint_sha256": statement["previous_checkpoint_sha256"],
        "activation_source_commit": source_sha,
    }


def validate_report(report: dict) -> dict:
    if not isinstance(report, dict) or frozenset(report) != REPORT_KEYS:
        raise AssertionError("invalid observer report fields")
    if report.get("schema") != REPORT_SCHEMA or report.get("algorithm") != ALGORITHM:
        raise AssertionError("invalid observer report envelope")
    statement = report.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != STATEMENT_KEYS:
        raise AssertionError("invalid observer statement fields")
    if statement.get("schema") != STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError("invalid observer statement boundary")
    observer_id = statement.get("observer_id")
    if not isinstance(observer_id, str) or observer_id not in PINNED_OBSERVERS:
        raise AssertionError("unknown observer id")
    material_verify.ed25519_verify(
        PINNED_OBSERVERS[observer_id],
        material_verify.decode_signature(report["signature"]),
        observation_message(statement),
    )
    return statement


def validate_bundle(bundle: dict, target: dict) -> None:
    if frozenset(bundle) != BUNDLE_KEYS or bundle.get("schema") != BUNDLE_SCHEMA:
        raise AssertionError("invalid observer bundle fields")
    if type(bundle.get("threshold")) is not int or bundle["threshold"] != THRESHOLD:
        raise AssertionError("invalid observer threshold")
    if bundle.get("production") is not False:
        raise AssertionError("production observer bundle forbidden in RUST-038")
    reports = bundle.get("reports")
    if not isinstance(reports, list) or not (THRESHOLD <= len(reports) <= len(PINNED_OBSERVERS)):
        raise AssertionError("invalid observer report count")

    statements = [validate_report(report) for report in reports]
    ids = [statement["observer_id"] for statement in statements]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("observer ids must be unique and sorted")

    matching = 0
    for statement in statements:
        if statement["activation_source_commit"] != target["activation_source_commit"]:
            raise AssertionError("observer source mismatch")
        same_epoch_parent = (
            statement["set_sequence"] == target["set_sequence"]
            and statement["previous_checkpoint_sha256"] == target["previous_checkpoint_sha256"]
        )
        exact = all(statement[key] == target[key] for key in target)
        if same_epoch_parent and not exact:
            raise AssertionError("observed cross-observer same-parent checkpoint fork")
        if not exact:
            raise AssertionError("observer report does not match canonical checkpoint")
        matching += 1
    if matching < THRESHOLD:
        raise AssertionError("observer quorum below threshold")


def verify(
    final_state_path: Path,
    external_floor_path: Path,
    first_rotation_path: Path,
    first_auth_path: Path,
    first_quorum_path: Path,
    second_rotation_path: Path,
    second_auth_path: Path,
    final_quorum_path: Path,
    prefix_journal_path: Path,
    prefix_checkpoint_path: Path,
    final_journal_path: Path,
    final_checkpoint_path: Path,
    observer_bundle_path: Path,
    expected_source_sha: str,
    required_floor_text: str,
) -> None:
    journal_verify.verify(
        final_state_path, external_floor_path, first_rotation_path, first_auth_path,
        first_quorum_path, second_rotation_path, second_auth_path, final_quorum_path,
        prefix_journal_path, prefix_checkpoint_path, final_journal_path,
        final_checkpoint_path, expected_source_sha, required_floor_text,
    )
    _, final_checkpoint = floor_verify.load_canonical(final_checkpoint_path, "final checkpoint")
    _, bundle = floor_verify.load_canonical(observer_bundle_path, "observer bundle")
    target = canonical_target(final_checkpoint, expected_source_sha)
    validate_bundle(bundle, target)
    ids = ",".join(report["statement"]["observer_id"] for report in bundle["reports"])
    print(
        "RUST-038 multi-observer checkpoint gossip: GREEN "
        f"source={expected_source_sha} threshold={THRESHOLD} observers={ids}"
    )


def main() -> None:
    if len(sys.argv) != 17 or sys.argv[1] != "verify":
        raise SystemExit("usage: rust_038_checkpoint_gossip_verify.py verify ... OBSERVER_BUNDLE SOURCE_SHA REQUIRED_FLOOR")
    args = [Path(value) for value in sys.argv[2:-2]]
    verify(*args, sys.argv[-2], sys.argv[-1])


if __name__ == "__main__":
    main()
