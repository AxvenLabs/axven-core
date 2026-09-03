#!/usr/bin/env python3
"""RUST-074: TEST-ONLY RUST-073 observer-rotation-journal checkpoint monitor verifier."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_072_multistep_monitor_rotation_journal_observer_set_rotation_verify as rotation2_verify
import rust_073_monitor_rotation_journal_observer_rotation_journal_verify as journal_verify

BUNDLE_SCHEMA = "axven-native-monitor-rotation-journal-observer-set-rotation-journal-checkpoint-monitor-bundle-v1"
REPORT_SCHEMA = "axven-native-monitor-rotation-journal-observer-set-rotation-journal-checkpoint-monitor-report-v1"
STATEMENT_SCHEMA = "axven-native-monitor-rotation-journal-observer-set-rotation-journal-checkpoint-monitor-statement-v1"
MONITOR_DOMAIN = b"AXVEN_NATIVE_MONITOR_ROTATION_JOURNAL_OBSERVER_SET_ROTATION_JOURNAL_CHECKPOINT_MONITOR_V1\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2

MONITOR_1_ID = "rust-074-test-only-monitor-rotation-journal-observer-rotation-journal-monitor-1-v1"
MONITOR_2_ID = "rust-074-test-only-monitor-rotation-journal-observer-rotation-journal-monitor-2-v1"
MONITOR_3_ID = "rust-074-test-only-monitor-rotation-journal-observer-rotation-journal-monitor-3-v1"
MONITOR_1_PUBLIC_KEY = bytes.fromhex("c2f38d34dafe402561da5a0a278e8a3255e0fc9c2e58c0209966a589fd07b631")
MONITOR_2_PUBLIC_KEY = bytes.fromhex("259145ad2655219b76837676ba31b9779035ffaa88c457a595d22e4a374527c2")
MONITOR_3_PUBLIC_KEY = bytes.fromhex("ba3b611e2882c1b6aa4b2ae3ec78ea0736e3ad99238353450171507a4b9f15b5")
PINNED_MONITORS = {
    MONITOR_1_ID: MONITOR_1_PUBLIC_KEY,
    MONITOR_2_ID: MONITOR_2_PUBLIC_KEY,
    MONITOR_3_ID: MONITOR_3_PUBLIC_KEY,
}

BUNDLE_KEYS = frozenset({"schema", "threshold", "reports", "production"})
REPORT_KEYS = frozenset({"schema", "algorithm", "statement", "signature"})
STATEMENT_KEYS = frozenset({
    "schema", "monitor_id",
    "monitor_rotation_journal_observer_rotation_journal_checkpoint_sha256",
    "monitor_rotation_journal_observer_rotation_journal_checkpoint_statement_sha256",
    "observer_set_sequence", "observer_set_sha256", "entry_count",
    "journal_sha256", "head_entry_sha256", "previous_checkpoint_sha256",
    "monitor_rotation_journal_checkpoint_sha256",
    "monitor_rotation_journal_checkpoint_statement_sha256",
    "observed_target_sha256", "activation_source_commit", "production",
})
TARGET_KEYS = frozenset(STATEMENT_KEYS - {"schema", "monitor_id", "production"})


def canonical(value: dict) -> bytes:
    return material_verify.canonical(value)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def checkpoint_target(checkpoint_raw: bytes, statement: dict) -> dict:
    if not isinstance(statement, dict) or frozenset(statement) != journal_verify.STATEMENT_KEYS:
        raise AssertionError("invalid RUST-074 canonical checkpoint statement fields")
    return {
        "monitor_rotation_journal_observer_rotation_journal_checkpoint_sha256": sha256(checkpoint_raw),
        "monitor_rotation_journal_observer_rotation_journal_checkpoint_statement_sha256": sha256(canonical(statement)),
        "observer_set_sequence": statement["observer_set_sequence"],
        "observer_set_sha256": statement["observer_set_sha256"],
        "entry_count": statement["entry_count"],
        "journal_sha256": statement["journal_sha256"],
        "head_entry_sha256": statement["head_entry_sha256"],
        "previous_checkpoint_sha256": statement["previous_checkpoint_sha256"],
        "monitor_rotation_journal_checkpoint_sha256": statement[
            "monitor_rotation_journal_checkpoint_sha256"
        ],
        "monitor_rotation_journal_checkpoint_statement_sha256": statement[
            "monitor_rotation_journal_checkpoint_statement_sha256"
        ],
        "observed_target_sha256": statement["observed_target_sha256"],
        "activation_source_commit": statement["activation_source_commit"],
    }


def monitor_message(statement: dict) -> bytes:
    raw = canonical(statement)
    return MONITOR_DOMAIN + len(raw).to_bytes(8, "big") + raw


def validate_report_envelope(report: dict) -> dict:
    if not isinstance(report, dict) or frozenset(report) != REPORT_KEYS:
        raise AssertionError("invalid RUST-074 observer-rotation-journal monitor report fields")
    if report.get("schema") != REPORT_SCHEMA or report.get("algorithm") != ALGORITHM:
        raise AssertionError("invalid RUST-074 observer-rotation-journal monitor report envelope")
    statement = report.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != STATEMENT_KEYS:
        raise AssertionError("invalid RUST-074 observer-rotation-journal monitor statement fields")
    if statement.get("schema") != STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError("invalid RUST-074 observer-rotation-journal monitor statement boundary")
    monitor_id = statement.get("monitor_id")
    if not isinstance(monitor_id, str) or monitor_id not in PINNED_MONITORS:
        raise AssertionError("unknown RUST-074 observer-rotation-journal checkpoint monitor")
    material_verify.ed25519_verify(
        PINNED_MONITORS[monitor_id],
        material_verify.decode_signature(report["signature"]),
        monitor_message(statement),
    )
    return statement


def statement_matches_target(statement: dict, target: dict) -> bool:
    return all(statement.get(key) == target[key] for key in TARGET_KEYS)


def validate_bundle(bundle: dict, target: dict) -> None:
    if (
        not isinstance(bundle, dict)
        or frozenset(bundle) != BUNDLE_KEYS
        or bundle.get("schema") != BUNDLE_SCHEMA
    ):
        raise AssertionError("invalid RUST-074 observer-rotation-journal monitor bundle fields")
    if type(bundle.get("threshold")) is not int or bundle["threshold"] != THRESHOLD:
        raise AssertionError("invalid RUST-074 observer-rotation-journal monitor threshold")
    if bundle.get("production") is not False:
        raise AssertionError("production RUST-074 observer-rotation-journal monitoring forbidden")
    reports = bundle.get("reports")
    if not isinstance(reports, list) or not (THRESHOLD <= len(reports) <= len(PINNED_MONITORS)):
        raise AssertionError("invalid RUST-074 observer-rotation-journal monitor report count")
    statements = [validate_report_envelope(report) for report in reports]
    ids = [statement["monitor_id"] for statement in statements]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("RUST-074 monitor ids must be unique and sorted")

    for statement in statements:
        if statement["activation_source_commit"] != target["activation_source_commit"]:
            raise AssertionError("RUST-074 monitor source mismatch")
        same_parent = (
            statement["observer_set_sequence"] == target["observer_set_sequence"]
            and statement["previous_checkpoint_sha256"] == target["previous_checkpoint_sha256"]
        )
        exact = statement_matches_target(statement, target)
        if same_parent and not exact:
            raise AssertionError("observed monitor same-parent RUST-073 observer rotation journal checkpoint fork")
        if not exact:
            raise AssertionError("RUST-074 monitor report does not match canonical RUST-073 checkpoint")


def validate_observed_fork_evidence(
    bundle: dict,
    canonical_target: dict,
    observed_checkpoint_raw: bytes,
    observed_checkpoint: dict,
    final_journal_raw: bytes,
) -> dict:
    observed_statement = journal_verify.validate_checkpoint_envelope(
        observed_checkpoint,
        final_journal_raw,
        rotation2_verify.FINAL_PINNED_OBSERVERS,
        "RUST-074 observed fork",
    )
    observed_target = checkpoint_target(observed_checkpoint_raw, observed_statement)
    same_parent = (
        observed_target["observer_set_sequence"] == canonical_target["observer_set_sequence"]
        and observed_target["previous_checkpoint_sha256"]
        == canonical_target["previous_checkpoint_sha256"]
    )
    if not same_parent or observed_target == canonical_target:
        raise AssertionError("RUST-074 observed checkpoint is not a distinct same-parent fork")
    reports = bundle.get("reports") if isinstance(bundle, dict) else None
    if not isinstance(reports, list):
        raise AssertionError("invalid RUST-074 observed-fork monitor bundle")
    matched = 0
    for report in reports:
        statement = validate_report_envelope(report)
        if statement_matches_target(statement, observed_target):
            matched += 1
    if matched < 1:
        raise AssertionError("no signed monitor report binds RUST-074 observed valid fork")
    return observed_target


def verify(*args) -> None:
    if len(args) != 114:
        raise AssertionError("unexpected RUST-074 verifier argument count")
    *path_args, expected_source_sha, required_floor_text = args
    if len(path_args) != 112:
        raise AssertionError("unexpected RUST-074 path count")
    base_paths = path_args[:111]
    monitor_bundle_path = path_args[111]

    journal_verify.verify(*base_paths, expected_source_sha, required_floor_text)

    final_journal_raw, _ = floor_verify.load_canonical(
        base_paths[109], "RUST-073 final observer rotation journal"
    )
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(
        base_paths[110], "RUST-073 final observer rotation checkpoint"
    )
    statement = journal_verify.validate_checkpoint_envelope(
        final_checkpoint,
        final_journal_raw,
        rotation2_verify.FINAL_PINNED_OBSERVERS,
        "RUST-074 canonical final",
    )
    target = checkpoint_target(final_checkpoint_raw, statement)
    if target["activation_source_commit"] != expected_source_sha:
        raise AssertionError("RUST-074 observer-rotation-journal checkpoint source mismatch")

    _, bundle = floor_verify.load_canonical(
        monitor_bundle_path, "RUST-074 observer-rotation-journal monitor bundle"
    )
    validate_bundle(bundle, target)
    ids = ",".join(report["statement"]["monitor_id"] for report in bundle["reports"])
    print(
        "RUST-074 observer-rotation-journal checkpoint monitoring: GREEN "
        f"source={expected_source_sha} threshold={THRESHOLD} monitors={ids} "
        f"checkpoint={target['monitor_rotation_journal_observer_rotation_journal_checkpoint_sha256']}"
    )


def main() -> None:
    if len(sys.argv) != 116 or sys.argv[1] != "verify":
        raise SystemExit(
            "usage: rust_074_monitor_rotation_journal_observer_rotation_journal_monitor_verify.py verify "
            "... FINAL_OBSERVER_ROTATION_CHECKPOINT MONITOR_BUNDLE SOURCE_SHA REQUIRED_FLOOR"
        )
    paths = [Path(value) for value in sys.argv[2:-2]]
    verify(*paths, sys.argv[-2], sys.argv[-1])


if __name__ == "__main__":
    main()
