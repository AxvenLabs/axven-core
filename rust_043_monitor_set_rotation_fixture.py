#!/usr/bin/env python3
"""RUST-043 TEST-only monitor-set rotation producer. Private seeds remain producer-side."""
from __future__ import annotations

import base64
import copy
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_042_observer_journal_monitor_verify as monitor_verify
import rust_043_monitor_set_rotation_verify as rotation_verify

OUT = Path("/tmp")
SEEDS = {
    monitor_verify.MONITOR_1_ID: "aa" * 32,
    monitor_verify.MONITOR_2_ID: "bb" * 32,
    monitor_verify.MONITOR_3_ID: "cc" * 32,
    rotation_verify.M4_ID: "dd" * 32,
}


def private_for(monitor_id: str, pins: dict[str, bytes]) -> Ed25519PrivateKey:
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[monitor_id]))
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if public != pins[monitor_id]:
        raise AssertionError("RUST-043 TEST-only monitor public-key pin mismatch")
    return private


def auth_rows(rotation_raw: bytes) -> list[dict]:
    message = rotation_verify.rotation_message(rotation_raw)
    return [
        {
            "monitor_id": monitor_id,
            "signature": base64.b64encode(private_for(monitor_id, rotation_verify.OLD_PINNED_MONITORS).sign(message)).decode("ascii"),
        }
        for monitor_id in sorted(rotation_verify.OLD_PINNED_MONITORS)
    ]


def successor_report(monitor_id: str, target: dict, set_sha: str) -> dict:
    statement = {
        "schema": rotation_verify.SUCCESSOR_STATEMENT_SCHEMA,
        "monitor_id": monitor_id,
        "monitor_set_sequence": rotation_verify.NEW_SET_SEQUENCE,
        "monitor_set_sha256": set_sha,
        **target,
        "production": False,
    }
    return {
        "schema": rotation_verify.SUCCESSOR_REPORT_SCHEMA,
        "algorithm": rotation_verify.ALGORITHM,
        "statement": statement,
        "signature": base64.b64encode(
            private_for(monitor_id, rotation_verify.NEW_PINNED_MONITORS).sign(rotation_verify.successor_message(statement))
        ).decode("ascii"),
    }


def bundle(reports: list[dict], set_sha: str) -> dict:
    return {
        "schema": rotation_verify.SUCCESSOR_BUNDLE_SCHEMA,
        "monitor_set_sequence": rotation_verify.NEW_SET_SEQUENCE,
        "monitor_set_sha256": set_sha,
        "threshold": rotation_verify.THRESHOLD,
        "reports": sorted(reports, key=lambda row: row["statement"]["monitor_id"]),
        "production": False,
    }


def main() -> None:
    if len(sys.argv) != 2 or len(sys.argv[1]) != 40 or any(c not in "0123456789abcdef" for c in sys.argv[1]):
        raise SystemExit("usage: rust_043_monitor_set_rotation_fixture.py SOURCE_SHA")
    source_sha = sys.argv[1]
    final_checkpoint_raw, final_checkpoint = floor_verify.load_canonical(
        OUT / "axven-rust041-final-observer-checkpoint.json", "final observer checkpoint"
    )
    fork_checkpoint_raw, fork_checkpoint = floor_verify.load_canonical(
        OUT / "axven-rust041-observed-fork-observer-checkpoint.json", "fork observer checkpoint"
    )
    old_bundle_raw, _ = floor_verify.load_canonical(OUT / "axven-rust042-monitor-bundle.json", "old monitor bundle")
    target = monitor_verify.checkpoint_target(final_checkpoint_raw, final_checkpoint["statement"])
    fork_target = monitor_verify.checkpoint_target(fork_checkpoint_raw, fork_checkpoint["statement"])
    if target["activation_source_commit"] != source_sha or fork_target["activation_source_commit"] != source_sha:
        raise AssertionError("RUST-043 checkpoint source mismatch")
    rotation = {
        "schema": rotation_verify.ROTATION_SCHEMA,
        "sequence": rotation_verify.NEW_SET_SEQUENCE,
        "from_set_sha256": rotation_verify.sha256(material_verify.canonical(rotation_verify.old_monitor_set())),
        "to_set": rotation_verify.new_monitor_set(),
        "revoked_monitor_ids": [rotation_verify.REVOKED_MONITOR_ID],
        "predecessor_monitor_bundle_sha256": hashlib.sha256(old_bundle_raw).hexdigest(),
        "checkpoint_sha256": target["checkpoint_sha256"],
        "activation_source_commit": source_sha,
        "production": False,
    }
    rotation_raw = material_verify.canonical(rotation)
    auth = {
        "schema": rotation_verify.ROTATION_AUTH_SCHEMA,
        "algorithm": rotation_verify.ALGORITHM,
        "threshold": rotation_verify.THRESHOLD,
        "payload_type": rotation_verify.ROTATION_PAYLOAD_TYPE,
        "payload_sha256": hashlib.sha256(rotation_raw).hexdigest(),
        "monitors": auth_rows(rotation_raw),
        "production": False,
    }
    set_sha = rotation_verify.sha256(material_verify.canonical(rotation_verify.new_monitor_set()))
    reports = [successor_report(monitor_id, target, set_sha) for monitor_id in sorted(rotation_verify.NEW_PINNED_MONITORS)]
    successor = bundle(reports, set_sha)
    fork_report = successor_report(rotation_verify.M4_ID, fork_target, set_sha)
    fork_successor = bundle([reports[0], reports[1], fork_report], set_sha)

    (OUT / "axven-rust043-monitor-set-rotation.json").write_bytes(rotation_raw)
    (OUT / "axven-rust043-monitor-set-rotation-auth.json").write_bytes(material_verify.canonical(auth))
    (OUT / "axven-rust043-successor-monitor-bundle.json").write_bytes(material_verify.canonical(successor))
    (OUT / "axven-rust043-successor-fork-monitor-bundle.json").write_bytes(material_verify.canonical(fork_successor))
    print("RUST-043 TEST-only monitor-set rotation fixture: GREEN")


if __name__ == "__main__":
    main()
