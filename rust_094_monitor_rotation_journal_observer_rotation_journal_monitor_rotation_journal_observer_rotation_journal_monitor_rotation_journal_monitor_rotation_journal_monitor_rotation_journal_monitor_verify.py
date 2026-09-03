#!/usr/bin/env python3
"""RUST-094: TEST-ONLY RUST-093 monitor-rotation-journal checkpoint monitor verifier."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_093_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_verify as journal_verify

BUNDLE_SCHEMA = "axven-native-rust094-monitor-rotation-journal-checkpoint-monitor-bundle-v1"
REPORT_SCHEMA = "axven-native-rust094-monitor-rotation-journal-checkpoint-monitor-report-v1"
STATEMENT_SCHEMA = "axven-native-rust094-monitor-rotation-journal-checkpoint-monitor-statement-v1"
MONITOR_DOMAIN = b"AXVEN_NATIVE_RUST094_MONITOR_ROTATION_JOURNAL_CHECKPOINT_MONITOR_V1\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2

MONITOR_1_ID = "rust-094-test-only-monitor-rotation-journal-monitor-1-v1"
MONITOR_2_ID = "rust-094-test-only-monitor-rotation-journal-monitor-2-v1"
MONITOR_3_ID = "rust-094-test-only-monitor-rotation-journal-monitor-3-v1"
MONITOR_1_PUBLIC_KEY = bytes.fromhex("7ea0e3bd52e207c9d3b0eba65c0704e66fca2d8e165a175218b174fc4160e413")
MONITOR_2_PUBLIC_KEY = bytes.fromhex("6b734a8eff246fe734b38d4046c148eee5f04fe87b3a0a423955a77956de066b")
MONITOR_3_PUBLIC_KEY = bytes.fromhex("8320a51977d8c38ca8a4927c670df5821e449761945e15e9efb26a1509d230ea")
PINNED_MONITORS = {
    MONITOR_1_ID: MONITOR_1_PUBLIC_KEY,
    MONITOR_2_ID: MONITOR_2_PUBLIC_KEY,
    MONITOR_3_ID: MONITOR_3_PUBLIC_KEY,
}

CHECKPOINT_SHA_KEY = (
    "monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_"
    "observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_"
    "monitor_rotation_journal_checkpoint_sha256"
)
CHECKPOINT_STATEMENT_SHA_KEY = (
    "monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_"
    "observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_"
    "monitor_rotation_journal_checkpoint_statement_sha256"
)

BUNDLE_KEYS = frozenset({"schema", "threshold", "reports", "production"})
REPORT_KEYS = frozenset({"schema", "algorithm", "statement", "signature"})
STATEMENT_KEYS = frozenset({
    "schema", "monitor_id", CHECKPOINT_SHA_KEY, CHECKPOINT_STATEMENT_SHA_KEY,
    "monitor_set_sequence", "monitor_set_sha256", "entry_count",
    "journal_sha256", "head_entry_sha256", "previous_checkpoint_sha256",
    "monitored_checkpoint_sha256", "monitored_checkpoint_statement_sha256",
    "observed_target_sha256", "activation_source_commit", "production",
})
TARGET_KEYS = frozenset(STATEMENT_KEYS - {"schema", "monitor_id", "production"})


def canonical(value: dict) -> bytes:
    return material_verify.canonical(value)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def checkpoint_target(checkpoint_raw: bytes, statement: dict) -> dict:
    if not isinstance(statement, dict) or frozenset(statement) != journal_verify.STATEMENT_KEYS:
        raise AssertionError("invalid RUST-094 canonical checkpoint statement fields")
    return {
        CHECKPOINT_SHA_KEY: sha256(checkpoint_raw),
        CHECKPOINT_STATEMENT_SHA_KEY: sha256(canonical(statement)),
        "monitor_set_sequence": statement["monitor_set_sequence"],
        "monitor_set_sha256": statement["monitor_set_sha256"],
        "entry_count": statement["entry_count"],
        "journal_sha256": statement["journal_sha256"],
        "head_entry_sha256": statement["head_entry_sha256"],
        "previous_checkpoint_sha256": statement["previous_checkpoint_sha256"],
        "monitored_checkpoint_sha256": statement["monitored_checkpoint_sha256"],
        "monitored_checkpoint_statement_sha256": statement["monitored_checkpoint_statement_sha256"],
        "observed_target_sha256": statement["observed_target_sha256"],
        "activation_source_commit": statement["activation_source_commit"],
    }


def monitor_message(statement: dict) -> bytes:
    raw = canonical(statement)
    return MONITOR_DOMAIN + len(raw).to_bytes(8, "big") + raw


def validate_report_envelope(report: dict) -> dict:
    if not isinstance(report, dict) or frozenset(report) != REPORT_KEYS:
        raise AssertionError("invalid RUST-094 monitor report fields")
    if report.get("schema") != REPORT_SCHEMA or report.get("algorithm") != ALGORITHM:
        raise AssertionError("invalid RUST-094 monitor report envelope")
    statement = report.get("statement")
    if not isinstance(statement, dict) or frozenset(statement) != STATEMENT_KEYS:
        raise AssertionError("invalid RUST-094 monitor statement fields")
    if statement.get("schema") != STATEMENT_SCHEMA or statement.get("production") is not False:
        raise AssertionError("invalid RUST-094 monitor statement boundary")
    monitor_id = statement.get("monitor_id")
    if not isinstance(monitor_id, str) or monitor_id not in PINNED_MONITORS:
        raise AssertionError("unknown RUST-094 checkpoint monitor")
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
        raise AssertionError("invalid RUST-094 monitor bundle fields")
    if type(bundle.get("threshold")) is not int or bundle["threshold"] != THRESHOLD:
        raise AssertionError("invalid RUST-094 monitor threshold")
    if bundle.get("production") is not False:
        raise AssertionError("production RUST-094 monitoring forbidden")
    reports = bundle.get("reports")
    if not isinstance(reports, list) or not (THRESHOLD <= len(reports) <= len(PINNED_MONITORS)):
        raise AssertionError("invalid RUST-094 monitor report count")
    statements = [validate_report_envelope(report) for report in reports]
    ids = [statement["monitor_id"] for statement in statements]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise AssertionError("RUST-094 monitor ids must be unique and sorted")

    for statement in statements:
        if statement["activation_source_commit"] != target["activation_source_commit"]:
            raise AssertionError("RUST-094 monitor source mismatch")
        same_parent = (
            statement["monitor_set_sequence"] == target["monitor_set_sequence"]
            and statement["previous_checkpoint_sha256"] == target["previous_checkpoint_sha256"]
        )
        exact = statement_matches_target(statement, target)
        if same_parent and not exact:
            raise AssertionError("observed monitor same-parent RUST-093 monitor rotation journal checkpoint fork")
        if not exact:
            raise AssertionError("RUST-094 monitor report does not match canonical RUST-093 checkpoint")


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
        journal_verify.rotation2_verify.FINAL_PINNED_MONITORS,
        "RUST-094 observed fork",
    )
    observed_target = checkpoint_target(observed_checkpoint_raw, observed_statement)
    same_parent = (
        observed_target["monitor_set_sequence"] == canonical_target["monitor_set_sequence"]
        and observed_target["previous_checkpoint_sha256"]
        == canonical_target["previous_checkpoint_sha256"]
    )
    if not same_parent or observed_target == canonical_target:
        raise AssertionError("RUST-094 observed checkpoint is not a distinct same-parent fork")
    reports = bundle.get("reports") if isinstance(bundle, dict) else None
    if not isinstance(reports, list):
        raise AssertionError("invalid RUST-094 observed-fork monitor bundle")
    matched = 0
    for report in reports:
        statement = validate_report_envelope(report)
        if statement_matches_target(statement, observed_target):
            matched += 1
    if matched < 1:
        raise AssertionError("no signed monitor report binds RUST-094 observed valid fork")
    return observed_target


def verify(*args) -> None:
    if len(args) != 169:
        raise AssertionError("unexpected RUST-094 verifier argument count")
    *path_args, expected_source_sha, required_floor_text = args
    if len(path_args) != 167:
        raise AssertionError("unexpected RUST-094 path count")
    base_paths = path_args[:166]
    monitor_bundle_path = path_args[166]

    journal_verify.verify(*base_paths, expected_source_sha, required_floor_text)

    final_journal_raw, _ = floor_verify.load_canonical(
        base_paths[164], "RUST-093 final monitor rotation journal"
    )
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(
        base_paths[165], "RUST-093 final monitor rotation checkpoint"
    )
    statement = journal_verify.validate_checkpoint_envelope(
        final_checkpoint,
        final_journal_raw,
        journal_verify.rotation2_verify.FINAL_PINNED_MONITORS,
        "RUST-094 canonical final",
    )
    target = checkpoint_target(final_checkpoint_raw, statement)
    if target["activation_source_commit"] != expected_source_sha:
        raise AssertionError("RUST-094 monitor-rotation-journal checkpoint source mismatch")

    _, bundle = floor_verify.load_canonical(
        monitor_bundle_path, "RUST-094 monitor-rotation-journal monitor bundle"
    )
    validate_bundle(bundle, target)
    ids = ",".join(report["statement"]["monitor_id"] for report in bundle["reports"])
    print(
        "RUST-094 RUST-093 journal checkpoint monitoring: GREEN "
        f"source={expected_source_sha} threshold={THRESHOLD} monitors={ids} "
        f"checkpoint={target[CHECKPOINT_SHA_KEY]}"
    )


def main() -> None:
    if len(sys.argv) != 171 or sys.argv[1] != "verify":
        raise SystemExit(
            "usage: rust_094_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_rotation_journal_monitor_verify.py verify "
            "... RUST093_FINAL_CHECKPOINT MONITOR_BUNDLE SOURCE_SHA REQUIRED_FLOOR"
        )
    paths = [Path(value) for value in sys.argv[2:-2]]
    verify(*paths, sys.argv[-2], sys.argv[-1])


if __name__ == "__main__":
    main()
