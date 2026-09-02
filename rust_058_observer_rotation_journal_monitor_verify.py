#!/usr/bin/env python3
"""RUST-058: TEST-ONLY observer-rotation-journal checkpoint monitor verifier."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_056_multistep_journal_monitor_journal_observer_rotation_verify as rotation2_verify
import rust_057_observer_rotation_journal_verify as journal_verify

BUNDLE_SCHEMA = "axven-native-journal-monitor-journal-observer-rotation-journal-checkpoint-monitor-bundle-v1"
REPORT_SCHEMA = "axven-native-journal-monitor-journal-observer-rotation-journal-checkpoint-monitor-report-v1"
STATEMENT_SCHEMA = "axven-native-journal-monitor-journal-observer-rotation-journal-checkpoint-monitor-statement-v1"
MONITOR_DOMAIN = b"AXVEN_NATIVE_JOURNAL_MONITOR_JOURNAL_OBSERVER_ROTATION_JOURNAL_CHECKPOINT_MONITOR_V1\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2

MONITOR_1_ID = "rust-058-test-only-observer-rotation-journal-monitor-1-v1"
MONITOR_2_ID = "rust-058-test-only-observer-rotation-journal-monitor-2-v1"
MONITOR_3_ID = "rust-058-test-only-observer-rotation-journal-monitor-3-v1"
MONITOR_1_PUBLIC_KEY = bytes.fromhex("60de5ecb8aa988422c22b1e20bfc40149ed94d1e90c05aea78c8f21be33170b0")
MONITOR_2_PUBLIC_KEY = bytes.fromhex("aaba072ca1732db64ea1556bef5688465d2cbf5e289018041adc32b4ed202b2b")
MONITOR_3_PUBLIC_KEY = bytes.fromhex("1660d273222b2922dfa2310bab8cc411029b3e672eef744ed50d60486ce8efab")
PINNED_MONITORS = {
    MONITOR_1_ID: MONITOR_1_PUBLIC_KEY,
    MONITOR_2_ID: MONITOR_2_PUBLIC_KEY,
    MONITOR_3_ID: MONITOR_3_PUBLIC_KEY,
}

BUNDLE_KEYS = frozenset({"schema", "threshold", "reports", "production"})
REPORT_KEYS = frozenset({"schema", "algorithm", "statement", "signature"})
STATEMENT_KEYS = frozenset({
    "schema", "monitor_id",
    "observer_rotation_journal_checkpoint_sha256",
    "observer_rotation_journal_checkpoint_statement_sha256",
    "observer_set_sequence", "observer_set_sha256", "entry_count",
    "journal_sha256", "head_entry_sha256", "previous_checkpoint_sha256",
    "observed_checkpoint_sha256", "observed_checkpoint_statement_sha256",
    "journal_observer_checkpoint_sha256", "monitor_journal_checkpoint_sha256",
    "monitor_journal_checkpoint_statement_sha256", "activation_source_commit",
    "production",
})
TARGET_KEYS = frozenset(STATEMENT_KEYS - {"schema", "monitor_id", "production"})


def canonical(value: dict) -> bytes:
    return material_verify.canonical(value)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def checkpoint_target(checkpoint_raw: bytes, statement: dict) -> dict:
    return {
        "observer_rotation_journal_checkpoint_sha256": sha256(checkpoint_raw),
        "observer_rotation_journal_checkpoint_statement_sha256": sha256(canonical(statement)),
        "observer_set_sequence": statement["observer_set_sequence"],
        "observer_set_sha256": statement["observer_set_sha256"],
        "entry_count": statement["entry_count"],
        "journal_sha256": statement["journal_sha256"],
        "head_entry_sha256": statement["head_entry_sha256"],
        "previous_checkpoint_sha256": statement["previous_checkpoint_sha256"],
        "observed_checkpoint_sha256": statement["observed_checkpoint_sha256"],
        "observed_checkpoint_statement_sha256": statement["observed_checkpoint_statement_sha256"],
        "journal_observer_checkpoint_sha256": statement["journal_observer_checkpoint_sha256"],
        "monitor_journal_checkpoint_sha256": statement["monitor_journal_checkpoint_sha256"],
        "monitor_journal_checkpoint_statement_sha256": statement[
            "monitor_journal_checkpoint_statement_sha256"
        ],
        "activation_source_commit": statement["activation_source_commit"],
    }


def monitor_message(statement: dict) -> bytes:
    raw = canonical(statement)
    return MONITOR_DOMAIN + len(raw).to_bytes(8, "big") + raw


def validate_report_envelope(report: dict) -> dict:
    if not isinstance(report, dict) or frozenset(report) != REPORT_KEYS:
        raise AssertionError("invalid observer-rotation-journal monitor report fields")
    if report.get("schema") != REPORT_SCHEMA or report.get("algorithm") != ALGORITHM:
        raise AssertionError("invalid observer-rotation-journal monitor report envelope")
    statement = report.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != STATEMENT_KEYS:
        raise AssertionError("invalid observer-rotation-journal monitor statement fields")
    if statement.get("schema") != STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError("invalid observer-rotation-journal monitor statement boundary")
    monitor_id = statement.get("monitor_id")
    if not isinstance(monitor_id, str) or monitor_id not in PINNED_MONITORS:
        raise AssertionError("unknown observer-rotation-journal checkpoint monitor")
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
        raise AssertionError("invalid observer-rotation-journal monitor bundle fields")
    if type(bundle.get("threshold")) is not int or bundle["threshold"] != THRESHOLD:
        raise AssertionError("invalid observer-rotation-journal monitor threshold")
    if bundle.get("production") is not False:
        raise AssertionError("production observer-rotation-journal monitoring forbidden in RUST-058")
    reports = bundle.get("reports")
    if not isinstance(reports, list) or not (THRESHOLD <= len(reports) <= len(PINNED_MONITORS)):
        raise AssertionError("invalid observer-rotation-journal monitor report count")
    statements = [validate_report_envelope(report) for report in reports]
    ids = [statement["monitor_id"] for statement in statements]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("observer-rotation-journal monitor ids must be unique and sorted")

    for statement in statements:
        same_parent = (
            statement["observer_set_sequence"] == target["observer_set_sequence"]
            and statement["previous_checkpoint_sha256"] == target["previous_checkpoint_sha256"]
        )
        exact = statement_matches_target(statement, target)
        if same_parent and not exact:
            raise AssertionError("observed monitor same-parent observer-rotation-journal checkpoint fork")
        if not exact:
            raise AssertionError(
                "monitor report does not match canonical observer-rotation-journal checkpoint"
            )


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
        "RUST-058 observed fork",
    )
    observed_target = checkpoint_target(observed_checkpoint_raw, observed_statement)
    same_parent = (
        observed_target["observer_set_sequence"] == canonical_target["observer_set_sequence"]
        and observed_target["previous_checkpoint_sha256"]
        == canonical_target["previous_checkpoint_sha256"]
    )
    if not same_parent or observed_target == canonical_target:
        raise AssertionError(
            "observed observer-rotation-journal checkpoint is not a distinct same-parent fork"
        )
    reports = bundle.get("reports") if isinstance(bundle, dict) else None
    if not isinstance(reports, list):
        raise AssertionError("invalid observed-fork monitor bundle")
    matched = 0
    for report in reports:
        statement = validate_report_envelope(report)
        if statement_matches_target(statement, observed_target):
            matched += 1
    if matched < 1:
        raise AssertionError("no signed monitor report binds observed valid fork")
    return observed_target


def verify(*args) -> None:
    if len(args) != 70:
        raise AssertionError("unexpected RUST-058 verifier argument count")
    *path_args, expected_source_sha, required_floor_text = args
    if len(path_args) != 68:
        raise AssertionError("unexpected RUST-058 path count")
    base_paths = path_args[:67]
    monitor_bundle_path = path_args[67]

    journal_verify.verify(*base_paths, expected_source_sha, required_floor_text)

    final_journal_raw, _ = floor_verify.load_canonical(
        base_paths[-2], "final observer-rotation journal"
    )
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(
        base_paths[-1], "final observer-rotation checkpoint"
    )
    statement = journal_verify.validate_checkpoint_envelope(
        final_checkpoint,
        final_journal_raw,
        rotation2_verify.FINAL_PINNED_OBSERVERS,
        "RUST-058 canonical final",
    )
    target = checkpoint_target(final_checkpoint_raw, statement)
    if target["activation_source_commit"] != expected_source_sha:
        raise AssertionError("RUST-058 observer-rotation-journal checkpoint source mismatch")

    _, bundle = floor_verify.load_canonical(
        monitor_bundle_path, "observer-rotation-journal monitor bundle"
    )
    validate_bundle(bundle, target)
    ids = ",".join(report["statement"]["monitor_id"] for report in bundle["reports"])
    print(
        "RUST-058 observer-rotation-journal checkpoint monitoring: GREEN "
        f"source={expected_source_sha} threshold={THRESHOLD} monitors={ids} "
        f"checkpoint={target['observer_rotation_journal_checkpoint_sha256']}"
    )


def main() -> None:
    if len(sys.argv) != 72 or sys.argv[1] != "verify":
        raise SystemExit(
            "usage: rust_058_observer_rotation_journal_monitor_verify.py verify "
            "... FINAL_OBSERVER_ROTATION_CHECKPOINT MONITOR_BUNDLE SOURCE_SHA REQUIRED_FLOOR"
        )
    paths = [Path(value) for value in sys.argv[2:-2]]
    verify(*paths, sys.argv[-2], sys.argv[-1])


if __name__ == "__main__":
    main()
