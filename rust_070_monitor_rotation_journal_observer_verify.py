#!/usr/bin/env python3
"""RUST-070: TEST-ONLY RUST-069 monitor-rotation-journal checkpoint observation verifier."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_068_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_verify as rotation2_verify
import rust_069_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_verify as journal_verify

BUNDLE_SCHEMA = "axven-native-monitor-rotation-journal-checkpoint-observation-bundle-v1"
REPORT_SCHEMA = "axven-native-monitor-rotation-journal-checkpoint-observation-v1"
STATEMENT_SCHEMA = "axven-native-monitor-rotation-journal-checkpoint-observation-statement-v1"
OBSERVATION_DOMAIN = b"AXVEN_NATIVE_MONITOR_ROTATION_JOURNAL_CHECKPOINT_OBSERVATION_V1\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2

OBSERVER_1_ID = "rust-070-test-only-monitor-rotation-journal-observer-1-v1"
OBSERVER_2_ID = "rust-070-test-only-monitor-rotation-journal-observer-2-v1"
OBSERVER_3_ID = "rust-070-test-only-monitor-rotation-journal-observer-3-v1"
OBSERVER_1_PUBLIC_KEY = bytes.fromhex("ba3b611e2882c1b6aa4b2ae3ec78ea0736e3ad99238353450171507a4b9f15b5")
OBSERVER_2_PUBLIC_KEY = bytes.fromhex("8e4190cd68fdc07dda0c59e6cb073efd2d9311d622a38a32df6885b4a4121551")
OBSERVER_3_PUBLIC_KEY = bytes.fromhex("0a81997d7673889d50f91fa0cf664f1c7a6ababd03f71cf0fe5d68ad7576d337")
PINNED_OBSERVERS = {
    OBSERVER_1_ID: OBSERVER_1_PUBLIC_KEY,
    OBSERVER_2_ID: OBSERVER_2_PUBLIC_KEY,
    OBSERVER_3_ID: OBSERVER_3_PUBLIC_KEY,
}

BUNDLE_KEYS = frozenset({"schema", "threshold", "reports", "production"})
REPORT_KEYS = frozenset({"schema", "algorithm", "statement", "signature"})
TARGET_KEYS = frozenset({
    "checkpoint_sha256", "checkpoint_statement_sha256",
    "monitor_set_sequence", "monitor_set_sha256", "entry_count",
    "journal_sha256", "head_entry_sha256", "previous_checkpoint_sha256",
    "monitored_checkpoint_sha256", "monitored_checkpoint_statement_sha256",
    "observed_target_sha256", "activation_source_commit",
})
STATEMENT_KEYS = frozenset({"schema", "observer_id", *TARGET_KEYS, "production"})


def canonical(value: dict) -> bytes:
    return material_verify.canonical(value)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def observation_message(statement: dict) -> bytes:
    raw = canonical(statement)
    return OBSERVATION_DOMAIN + len(raw).to_bytes(8, "big") + raw


def canonical_target(checkpoint_raw: bytes, checkpoint: dict, source_sha: str) -> dict:
    statement = checkpoint.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != journal_verify.STATEMENT_KEYS:
        raise AssertionError("missing final RUST-069 monitor rotation journal checkpoint statement")
    if statement.get("schema") != journal_verify.STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError("invalid final RUST-069 monitor rotation journal checkpoint statement boundary")
    if statement.get("activation_source_commit") != source_sha:
        raise AssertionError("final RUST-069 monitor rotation journal checkpoint source mismatch")
    return {
        "checkpoint_sha256": sha256(checkpoint_raw),
        "checkpoint_statement_sha256": sha256(canonical(statement)),
        "monitor_set_sequence": statement["monitor_set_sequence"],
        "monitor_set_sha256": statement["monitor_set_sha256"],
        "entry_count": statement["entry_count"],
        "journal_sha256": statement["journal_sha256"],
        "head_entry_sha256": statement["head_entry_sha256"],
        "previous_checkpoint_sha256": statement["previous_checkpoint_sha256"],
        "monitored_checkpoint_sha256": statement["monitored_checkpoint_sha256"],
        "monitored_checkpoint_statement_sha256": statement[
            "monitored_checkpoint_statement_sha256"
        ],
        "observed_target_sha256": statement["observed_target_sha256"],
        "activation_source_commit": source_sha,
    }


def validate_report(report: dict) -> dict:
    if not isinstance(report, dict) or frozenset(report) != REPORT_KEYS:
        raise AssertionError("invalid RUST-070 observer report fields")
    if report.get("schema") != REPORT_SCHEMA or report.get("algorithm") != ALGORITHM:
        raise AssertionError("invalid RUST-070 observer report envelope")
    statement = report.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != STATEMENT_KEYS:
        raise AssertionError("invalid RUST-070 observer statement fields")
    if statement.get("schema") != STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError("invalid RUST-070 observer statement boundary")
    observer_id = statement.get("observer_id")
    if not isinstance(observer_id, str) or observer_id not in PINNED_OBSERVERS:
        raise AssertionError("unknown RUST-070 monitor-rotation-journal observer id")
    material_verify.ed25519_verify(
        PINNED_OBSERVERS[observer_id],
        material_verify.decode_signature(report["signature"]),
        observation_message(statement),
    )
    return statement


def validate_bundle(bundle: dict, target: dict) -> None:
    if not isinstance(bundle, dict) or frozenset(bundle) != BUNDLE_KEYS or bundle.get("schema") != BUNDLE_SCHEMA:
        raise AssertionError("invalid RUST-070 monitor-rotation-journal observer bundle fields")
    if type(bundle.get("threshold")) is not int or bundle["threshold"] != THRESHOLD:
        raise AssertionError("invalid RUST-070 monitor-rotation-journal observer threshold")
    if bundle.get("production") is not False:
        raise AssertionError("production monitor-rotation-journal observer bundle forbidden in RUST-070")
    reports = bundle.get("reports")
    if not isinstance(reports, list) or not (THRESHOLD <= len(reports) <= len(PINNED_OBSERVERS)):
        raise AssertionError("invalid RUST-070 monitor-rotation-journal observer report count")

    statements = [validate_report(report) for report in reports]
    ids = [statement["observer_id"] for statement in statements]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("RUST-070 monitor-rotation-journal observer ids must be unique and sorted")

    matching = 0
    for statement in statements:
        if statement["activation_source_commit"] != target["activation_source_commit"]:
            raise AssertionError("RUST-070 monitor-rotation-journal observer source mismatch")
        same_epoch_parent = (
            statement["monitor_set_sequence"] == target["monitor_set_sequence"]
            and statement["previous_checkpoint_sha256"] == target["previous_checkpoint_sha256"]
        )
        exact = all(statement[key] == target[key] for key in TARGET_KEYS)
        if same_epoch_parent and not exact:
            raise AssertionError(
                "observed cross-observer same-parent RUST-069 monitor rotation journal checkpoint fork"
            )
        if not exact:
            raise AssertionError("RUST-070 observer report does not match canonical RUST-069 checkpoint")
        matching += 1
    if matching < THRESHOLD:
        raise AssertionError("RUST-070 monitor-rotation-journal observer quorum below threshold")


def verify(*args) -> None:
    if len(args) != 103:
        raise AssertionError("unexpected RUST-070 verifier argument count")
    *base_paths, observation_bundle_path, expected_source_sha, required_floor_text = args
    if len(base_paths) != 100:
        raise AssertionError("unexpected RUST-070 base path count")

    journal_verify.verify(*base_paths, expected_source_sha, required_floor_text)

    final_journal_raw, _ = floor_verify.load_canonical(
        base_paths[-2], "RUST-069 final monitor rotation journal"
    )
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(
        base_paths[-1], "RUST-069 final monitor rotation checkpoint"
    )
    journal_verify.validate_checkpoint_envelope(
        final_checkpoint,
        final_journal_raw,
        rotation2_verify.FINAL_PINNED_MONITORS,
        "RUST-070 canonical final",
    )
    _, bundle = floor_verify.load_canonical(
        observation_bundle_path, "RUST-070 monitor-rotation-journal observer bundle"
    )
    target = canonical_target(final_checkpoint_raw, final_checkpoint, expected_source_sha)
    validate_bundle(bundle, target)
    ids = ",".join(report["statement"]["observer_id"] for report in bundle["reports"])
    print(
        "RUST-070 monitor-rotation-journal checkpoint observation: GREEN "
        f"source={expected_source_sha} threshold={THRESHOLD} observers={ids} "
        f"checkpoint={target['checkpoint_sha256']}"
    )


def main() -> None:
    if len(sys.argv) != 105 or sys.argv[1] != "verify":
        raise SystemExit(
            "usage: rust_070_monitor_rotation_journal_observer_verify.py verify "
            "... FINAL_MONITOR_ROTATION_JOURNAL FINAL_MONITOR_ROTATION_CHECKPOINT "
            "OBSERVATION_BUNDLE SOURCE_SHA REQUIRED_FLOOR"
        )
    paths = [Path(value) for value in sys.argv[2:-2]]
    verify(*paths, sys.argv[-2], sys.argv[-1])


if __name__ == "__main__":
    main()
