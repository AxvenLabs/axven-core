#!/usr/bin/env python3
"""RUST-042 TEST-only monitor producer. Private monitor seeds stay producer-side."""
from __future__ import annotations

import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_042_observer_journal_monitor_verify as monitor_verify

OUT = Path("/tmp")
SEEDS = {
    monitor_verify.MONITOR_1_ID: "aa" * 32,
    monitor_verify.MONITOR_2_ID: "bb" * 32,
    monitor_verify.MONITOR_3_ID: "cc" * 32,
}


def private_for(monitor_id: str) -> Ed25519PrivateKey:
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[monitor_id]))
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if public != monitor_verify.PINNED_MONITORS[monitor_id]:
        raise AssertionError("RUST-042 TEST-only monitor public-key pin mismatch")
    return private


def report(monitor_id: str, target: dict) -> dict:
    statement = {
        "schema": monitor_verify.STATEMENT_SCHEMA,
        "monitor_id": monitor_id,
        **target,
        "production": False,
    }
    return {
        "schema": monitor_verify.REPORT_SCHEMA,
        "algorithm": monitor_verify.ALGORITHM,
        "statement": statement,
        "signature": base64.b64encode(private_for(monitor_id).sign(monitor_verify.monitor_message(statement))).decode("ascii"),
    }


def bundle(reports: list[dict]) -> dict:
    return {
        "schema": monitor_verify.BUNDLE_SCHEMA,
        "threshold": monitor_verify.THRESHOLD,
        "reports": sorted(reports, key=lambda row: row["statement"]["monitor_id"]),
        "production": False,
    }


def main() -> None:
    if len(sys.argv) != 2 or len(sys.argv[1]) != 40 or any(c not in "0123456789abcdef" for c in sys.argv[1]):
        raise SystemExit("usage: rust_042_observer_journal_monitor_fixture.py SOURCE_SHA")
    source_sha = sys.argv[1]
    final_raw, final_checkpoint = floor_verify.load_canonical(OUT / "axven-rust041-final-observer-checkpoint.json", "final observer checkpoint")
    fork_raw, fork_checkpoint = floor_verify.load_canonical(OUT / "axven-rust041-observed-fork-observer-checkpoint.json", "fork observer checkpoint")
    canonical_target = monitor_verify.checkpoint_target(final_raw, final_checkpoint["statement"])
    fork_target = monitor_verify.checkpoint_target(fork_raw, fork_checkpoint["statement"])
    if canonical_target["activation_source_commit"] != source_sha or fork_target["activation_source_commit"] != source_sha:
        raise AssertionError("RUST-042 checkpoint source mismatch")
    canonical_reports = [report(monitor_id, canonical_target) for monitor_id in sorted(monitor_verify.PINNED_MONITORS)]
    canonical_bundle = bundle(canonical_reports)
    split_bundle = bundle([
        report(monitor_verify.MONITOR_1_ID, canonical_target),
        report(monitor_verify.MONITOR_2_ID, canonical_target),
        report(monitor_verify.MONITOR_3_ID, fork_target),
    ])
    (OUT / "axven-rust042-monitor-bundle.json").write_bytes(material_verify.canonical(canonical_bundle))
    (OUT / "axven-rust042-observed-fork-monitor-bundle.json").write_bytes(material_verify.canonical(split_bundle))
    print("RUST-042 TEST-only observer-journal monitor fixture: GREEN")


if __name__ == "__main__":
    main()
