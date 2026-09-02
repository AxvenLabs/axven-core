#!/usr/bin/env python3
"""RUST-054: TEST-ONLY journal-monitor-rotation-journal checkpoint observation verifier."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_052_multistep_journal_monitor_rotation_verify as rotation2_verify
import rust_053_journal_monitor_rotation_journal_verify as journal_verify

BUNDLE_SCHEMA = "axven-native-journal-monitor-rotation-journal-checkpoint-observation-bundle-v1"
REPORT_SCHEMA = "axven-native-journal-monitor-rotation-journal-checkpoint-observation-v1"
STATEMENT_SCHEMA = "axven-native-journal-monitor-rotation-journal-checkpoint-observation-statement-v1"
OBSERVATION_DOMAIN = b"AXVEN_NATIVE_JOURNAL_MONITOR_ROTATION_JOURNAL_CHECKPOINT_OBSERVATION_V1\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2

OBSERVER_1_ID = "rust-054-test-only-journal-monitor-journal-observer-1-v1"
OBSERVER_2_ID = "rust-054-test-only-journal-monitor-journal-observer-2-v1"
OBSERVER_3_ID = "rust-054-test-only-journal-monitor-journal-observer-3-v1"
OBSERVER_1_PUBLIC_KEY = bytes.fromhex("e5145a37d984d244ce11e69388cb36dedc828c1a277ca347d50f5076a60959e8")
OBSERVER_2_PUBLIC_KEY = bytes.fromhex("248acbdbaf9e050196de704bea2d68770e519150d103b587dae2d9cad53dd930")
OBSERVER_3_PUBLIC_KEY = bytes.fromhex("7d59c5623dd40a74aa4d5a32ac645d3b3f95daeae4c22be25476dd6a486f7382")
PINNED_OBSERVERS = {
    OBSERVER_1_ID: OBSERVER_1_PUBLIC_KEY,
    OBSERVER_2_ID: OBSERVER_2_PUBLIC_KEY,
    OBSERVER_3_ID: OBSERVER_3_PUBLIC_KEY,
}

BUNDLE_KEYS = frozenset({"schema", "threshold", "reports", "production"})
REPORT_KEYS = frozenset({"schema", "algorithm", "statement", "signature"})
STATEMENT_KEYS = frozenset({
    "schema", "observer_id", "checkpoint_sha256", "checkpoint_statement_sha256",
    "monitor_set_sequence", "monitor_set_sha256", "entry_count", "journal_sha256",
    "head_entry_sha256", "previous_checkpoint_sha256", "journal_observer_checkpoint_sha256",
    "monitor_journal_checkpoint_sha256", "monitor_journal_checkpoint_statement_sha256",
    "activation_source_commit", "production",
})


def canonical(value: dict) -> bytes:
    return material_verify.canonical(value)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def observation_message(statement: dict) -> bytes:
    raw = canonical(statement)
    return OBSERVATION_DOMAIN + len(raw).to_bytes(8, "big") + raw


def canonical_target(checkpoint_raw: bytes, checkpoint: dict, source_sha: str) -> dict:
    statement = checkpoint.get("statement")
    if not isinstance(statement, dict):
        raise AssertionError("missing final journal-monitor-journal checkpoint statement")
    if statement.get("activation_source_commit") != source_sha:
        raise AssertionError("final journal-monitor-journal checkpoint source mismatch")
    return {
        "checkpoint_sha256": sha256(checkpoint_raw),
        "checkpoint_statement_sha256": sha256(canonical(statement)),
        "monitor_set_sequence": statement["monitor_set_sequence"],
        "monitor_set_sha256": statement["monitor_set_sha256"],
        "entry_count": statement["entry_count"],
        "journal_sha256": statement["journal_sha256"],
        "head_entry_sha256": statement["head_entry_sha256"],
        "previous_checkpoint_sha256": statement["previous_checkpoint_sha256"],
        "journal_observer_checkpoint_sha256": statement["journal_observer_checkpoint_sha256"],
        "monitor_journal_checkpoint_sha256": statement["monitor_journal_checkpoint_sha256"],
        "monitor_journal_checkpoint_statement_sha256": statement[
            "monitor_journal_checkpoint_statement_sha256"
        ],
        "activation_source_commit": source_sha,
    }


def validate_report(report: dict) -> dict:
    if not isinstance(report, dict) or frozenset(report) != REPORT_KEYS:
        raise AssertionError("invalid journal-monitor-journal observer report fields")
    if report.get("schema") != REPORT_SCHEMA or report.get("algorithm") != ALGORITHM:
        raise AssertionError("invalid journal-monitor-journal observer report envelope")
    statement = report.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != STATEMENT_KEYS:
        raise AssertionError("invalid journal-monitor-journal observer statement fields")
    if statement.get("schema") != STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError("invalid journal-monitor-journal observer statement boundary")
    observer_id = statement.get("observer_id")
    if not isinstance(observer_id, str) or observer_id not in PINNED_OBSERVERS:
        raise AssertionError("unknown journal-monitor-journal observer id")
    material_verify.ed25519_verify(
        PINNED_OBSERVERS[observer_id],
        material_verify.decode_signature(report["signature"]),
        observation_message(statement),
    )
    return statement


def validate_bundle(bundle: dict, target: dict) -> None:
    if not isinstance(bundle, dict) or frozenset(bundle) != BUNDLE_KEYS or bundle.get("schema") != BUNDLE_SCHEMA:
        raise AssertionError("invalid journal-monitor-journal observer bundle fields")
    if type(bundle.get("threshold")) is not int or bundle["threshold"] != THRESHOLD:
        raise AssertionError("invalid journal-monitor-journal observer threshold")
    if bundle.get("production") is not False:
        raise AssertionError("production journal-monitor-journal observer bundle forbidden in RUST-054")
    reports = bundle.get("reports")
    if not isinstance(reports, list) or not (THRESHOLD <= len(reports) <= len(PINNED_OBSERVERS)):
        raise AssertionError("invalid journal-monitor-journal observer report count")

    statements = [validate_report(report) for report in reports]
    ids = [statement["observer_id"] for statement in statements]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("journal-monitor-journal observer ids must be unique and sorted")

    matching = 0
    for statement in statements:
        if statement["activation_source_commit"] != target["activation_source_commit"]:
            raise AssertionError("journal-monitor-journal observer source mismatch")
        same_epoch_parent = (
            statement["monitor_set_sequence"] == target["monitor_set_sequence"]
            and statement["previous_checkpoint_sha256"] == target["previous_checkpoint_sha256"]
        )
        exact = all(statement[key] == target[key] for key in target)
        if same_epoch_parent and not exact:
            raise AssertionError(
                "observed cross-observer same-parent journal-monitor-rotation-journal checkpoint fork"
            )
        if not exact:
            raise AssertionError(
                "journal-monitor-journal observer report does not match canonical checkpoint"
            )
        matching += 1
    if matching < THRESHOLD:
        raise AssertionError("journal-monitor-journal observer quorum below threshold")


def verify(*args) -> None:
    if len(args) != 59:
        raise AssertionError("unexpected RUST-054 verifier argument count")
    *base_paths, observation_bundle_path, expected_source_sha, required_floor_text = args
    if len(base_paths) != 56:
        raise AssertionError("unexpected RUST-054 base path count")

    journal_verify.verify(*base_paths, expected_source_sha, required_floor_text)

    final_journal_raw, _ = floor_verify.load_canonical(
        base_paths[-2], "final journal-monitor journal"
    )
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(
        base_paths[-1], "final journal-monitor checkpoint"
    )
    journal_verify.validate_checkpoint_envelope(
        final_checkpoint,
        final_journal_raw,
        rotation2_verify.FINAL_PINNED_MONITORS,
        "RUST-054 canonical final",
    )
    _, bundle = floor_verify.load_canonical(
        observation_bundle_path, "journal-monitor-journal observer bundle"
    )
    target = canonical_target(final_checkpoint_raw, final_checkpoint, expected_source_sha)
    validate_bundle(bundle, target)
    ids = ",".join(report["statement"]["observer_id"] for report in bundle["reports"])
    print(
        "RUST-054 journal-monitor-journal checkpoint observation: GREEN "
        f"source={expected_source_sha} threshold={THRESHOLD} observers={ids} "
        f"checkpoint={target['checkpoint_sha256']}"
    )


def main() -> None:
    if len(sys.argv) != 61 or sys.argv[1] != "verify":
        raise SystemExit(
            "usage: rust_054_journal_monitor_journal_gossip_verify.py verify "
            "... FINAL_JOURNAL_MONITOR_JOURNAL FINAL_JOURNAL_MONITOR_CHECKPOINT "
            "OBSERVATION_BUNDLE SOURCE_SHA REQUIRED_FLOOR"
        )
    paths = [Path(value) for value in sys.argv[2:-2]]
    verify(*paths, sys.argv[-2], sys.argv[-1])


if __name__ == "__main__":
    main()
