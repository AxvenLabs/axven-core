#!/usr/bin/env python3
"""RUST-042: TEST-ONLY multi-monitor observer-journal checkpoint gossip verifier."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_040_multistep_observer_rotation_verify as rotation2_verify
import rust_041_observer_rotation_journal_verify as journal_verify

BUNDLE_SCHEMA = "axven-native-observer-journal-checkpoint-monitor-bundle-v1"
REPORT_SCHEMA = "axven-native-observer-journal-checkpoint-monitor-report-v1"
STATEMENT_SCHEMA = "axven-native-observer-journal-checkpoint-monitor-statement-v1"
MONITOR_DOMAIN = b"AXVEN_NATIVE_OBSERVER_JOURNAL_CHECKPOINT_MONITOR_V1\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2
MONITOR_1_ID = "rust-042-test-only-monitor-1-v1"
MONITOR_2_ID = "rust-042-test-only-monitor-2-v1"
MONITOR_3_ID = "rust-042-test-only-monitor-3-v1"
MONITOR_1_PUBLIC_KEY = bytes.fromhex("e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58")
MONITOR_2_PUBLIC_KEY = bytes.fromhex("7d59c5623dd40a74aa4d5a32ac645d3b3f95daeae4c22be25476dd6a486f7382")
MONITOR_3_PUBLIC_KEY = bytes.fromhex("ca57eed30e4a7274ef4c648f56f58f880b20d2ca25725d9e5c13c83c08c09aeb")
PINNED_MONITORS = {
    MONITOR_1_ID: MONITOR_1_PUBLIC_KEY,
    MONITOR_2_ID: MONITOR_2_PUBLIC_KEY,
    MONITOR_3_ID: MONITOR_3_PUBLIC_KEY,
}
BUNDLE_KEYS = frozenset({"schema", "threshold", "reports", "production"})
REPORT_KEYS = frozenset({"schema", "algorithm", "statement", "signature"})
STATEMENT_KEYS = frozenset({
    "schema", "monitor_id", "checkpoint_sha256", "observer_set_sequence", "observer_set_sha256",
    "journal_sha256", "head_entry_sha256", "previous_checkpoint_sha256", "checkpoint_statement_sha256",
    "activation_source_commit", "production",
})
TARGET_KEYS = frozenset(STATEMENT_KEYS - {"schema", "monitor_id", "production"})


def canonical(value: dict) -> bytes:
    return material_verify.canonical(value)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def checkpoint_target(checkpoint_raw: bytes, statement: dict) -> dict:
    return {
        "checkpoint_sha256": sha256(checkpoint_raw),
        "observer_set_sequence": statement["observer_set_sequence"],
        "observer_set_sha256": statement["observer_set_sha256"],
        "journal_sha256": statement["journal_sha256"],
        "head_entry_sha256": statement["head_entry_sha256"],
        "previous_checkpoint_sha256": statement["previous_checkpoint_sha256"],
        "checkpoint_statement_sha256": statement["checkpoint_statement_sha256"],
        "activation_source_commit": statement["activation_source_commit"],
    }


def monitor_message(statement: dict) -> bytes:
    raw = canonical(statement)
    return MONITOR_DOMAIN + len(raw).to_bytes(8, "big") + raw


def validate_report_envelope(report: dict) -> dict:
    if not isinstance(report, dict) or frozenset(report) != REPORT_KEYS:
        raise AssertionError("invalid monitor report fields")
    if report.get("schema") != REPORT_SCHEMA or report.get("algorithm") != ALGORITHM:
        raise AssertionError("invalid monitor report envelope")
    statement = report.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != STATEMENT_KEYS:
        raise AssertionError("invalid monitor statement fields")
    if statement.get("schema") != STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError("invalid monitor statement boundary")
    monitor_id = statement.get("monitor_id")
    if not isinstance(monitor_id, str) or monitor_id not in PINNED_MONITORS:
        raise AssertionError("unknown checkpoint monitor")
    material_verify.ed25519_verify(
        PINNED_MONITORS[monitor_id],
        material_verify.decode_signature(report["signature"]),
        monitor_message(statement),
    )
    return statement


def statement_matches_target(statement: dict, target: dict) -> bool:
    return all(statement.get(key) == target[key] for key in TARGET_KEYS)


def validate_bundle(bundle: dict, target: dict) -> None:
    if frozenset(bundle) != BUNDLE_KEYS or bundle.get("schema") != BUNDLE_SCHEMA:
        raise AssertionError("invalid monitor bundle fields")
    if type(bundle.get("threshold")) is not int or bundle["threshold"] != THRESHOLD:
        raise AssertionError("invalid monitor bundle threshold")
    if bundle.get("production") is not False:
        raise AssertionError("production checkpoint monitoring forbidden in RUST-042")
    reports = bundle.get("reports")
    if not isinstance(reports, list) or not (THRESHOLD <= len(reports) <= len(PINNED_MONITORS)):
        raise AssertionError("invalid monitor report count")
    statements = [validate_report_envelope(report) for report in reports]
    ids = [statement["monitor_id"] for statement in statements]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("checkpoint monitor ids must be unique and sorted")
    matching = 0
    for statement in statements:
        same_parent = (
            statement["observer_set_sequence"] == target["observer_set_sequence"]
            and statement["previous_checkpoint_sha256"] == target["previous_checkpoint_sha256"]
        )
        exact = statement_matches_target(statement, target)
        if same_parent and not exact:
            raise AssertionError("observed monitor same-parent observer-journal fork")
        if not exact:
            raise AssertionError("monitor report does not match canonical observer-journal checkpoint")
        matching += 1
    if matching < THRESHOLD:
        raise AssertionError("canonical monitor quorum below threshold")


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
        "observed monitor fork",
    )
    observed_target = checkpoint_target(observed_checkpoint_raw, observed_statement)
    same_parent = (
        observed_target["observer_set_sequence"] == canonical_target["observer_set_sequence"]
        and observed_target["previous_checkpoint_sha256"] == canonical_target["previous_checkpoint_sha256"]
    )
    if not same_parent or observed_target == canonical_target:
        raise AssertionError("observed checkpoint is not a distinct same-parent fork")
    reports = bundle.get("reports") if isinstance(bundle, dict) else None
    if not isinstance(reports, list):
        raise AssertionError("invalid observed fork monitor bundle")
    matched = 0
    for report in reports:
        statement = validate_report_envelope(report)
        if statement_matches_target(statement, observed_target):
            matched += 1
    if matched < 1:
        raise AssertionError("no signed monitor report binds observed valid fork")
    return observed_target


def verify(
    final_state_path: Path,
    external_floor_path: Path,
    first_witness_rotation_path: Path,
    first_witness_auth_path: Path,
    first_witness_quorum_path: Path,
    second_witness_rotation_path: Path,
    second_witness_auth_path: Path,
    final_witness_quorum_path: Path,
    prefix_witness_journal_path: Path,
    prefix_witness_checkpoint_path: Path,
    final_witness_journal_path: Path,
    final_witness_checkpoint_path: Path,
    old_observer_bundle_path: Path,
    first_observer_rotation_path: Path,
    first_observer_auth_path: Path,
    first_observer_successor_path: Path,
    second_observer_rotation_path: Path,
    second_observer_auth_path: Path,
    final_observer_bundle_path: Path,
    prefix_observer_journal_path: Path,
    prefix_observer_checkpoint_path: Path,
    final_observer_journal_path: Path,
    final_observer_checkpoint_path: Path,
    monitor_bundle_path: Path,
    expected_source_sha: str,
    required_floor_text: str,
) -> None:
    journal_verify.verify(
        final_state_path, external_floor_path, first_witness_rotation_path, first_witness_auth_path,
        first_witness_quorum_path, second_witness_rotation_path, second_witness_auth_path,
        final_witness_quorum_path, prefix_witness_journal_path, prefix_witness_checkpoint_path,
        final_witness_journal_path, final_witness_checkpoint_path, old_observer_bundle_path,
        first_observer_rotation_path, first_observer_auth_path, first_observer_successor_path,
        second_observer_rotation_path, second_observer_auth_path, final_observer_bundle_path,
        prefix_observer_journal_path, prefix_observer_checkpoint_path, final_observer_journal_path,
        final_observer_checkpoint_path, expected_source_sha, required_floor_text,
    )
    final_journal_raw, _ = floor_verify.load_canonical(final_observer_journal_path, "final observer journal")
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(final_observer_checkpoint_path, "final observer checkpoint")
    statement = journal_verify.validate_checkpoint_envelope(
        final_checkpoint, final_journal_raw, rotation2_verify.FINAL_PINNED_OBSERVERS, "final monitored"
    )
    target = checkpoint_target(final_checkpoint_raw, statement)
    _, bundle = floor_verify.load_canonical(monitor_bundle_path, "checkpoint monitor bundle")
    validate_bundle(bundle, target)
    ids = ",".join(report["statement"]["monitor_id"] for report in bundle["reports"])
    print(
        "RUST-042 observer-journal checkpoint monitoring: GREEN "
        f"source={expected_source_sha} threshold={THRESHOLD} monitors={ids} checkpoint={target['checkpoint_sha256']}"
    )


def main() -> None:
    if len(sys.argv) != 28 or sys.argv[1] != "verify":
        raise SystemExit("usage: rust_042_observer_journal_monitor_verify.py verify ... FINAL_OBS_CHECKPOINT MONITOR_BUNDLE SOURCE_SHA REQUIRED_FLOOR")
    paths = [Path(value) for value in sys.argv[2:-2]]
    verify(*paths, sys.argv[-2], sys.argv[-1])


if __name__ == "__main__":
    main()
