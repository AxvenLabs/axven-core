#!/usr/bin/env python3
"""RUST-112 TEST-ONLY second monitor-set rotation producer."""
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
import rust_110_rust109_checkpoint_monitor_verify as monitor_verify
import rust_111_rust110_checkpoint_monitor_rotation_verify as rotation1_verify
import rust_112_multistep_rust110_checkpoint_monitor_rotation_verify as rotation2_verify

OUT = Path("/tmp")
SEEDS = {
    monitor_verify.MONITOR_2_ID: "9c" * 32,
    monitor_verify.MONITOR_3_ID: "ac" * 32,
    rotation1_verify.M4_ID: "bc" * 32,
    rotation2_verify.M5_ID: "cc" * 32,
}


def private_for(monitor_id: str, pins: dict[str, bytes]) -> Ed25519PrivateKey:
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[monitor_id]))
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if public != pins[monitor_id]:
        raise AssertionError("RUST-112 TEST-only monitor public-key pin mismatch")
    return private


def auth_rows(rotation_raw: bytes) -> list[dict]:
    message = rotation2_verify.rotation_message(rotation_raw)
    return [
        {
            "monitor_id": monitor_id,
            "signature": base64.b64encode(
                private_for(monitor_id, rotation2_verify.PREDECESSOR_PINNED_MONITORS).sign(message)
            ).decode("ascii"),
        }
        for monitor_id in sorted(rotation2_verify.PREDECESSOR_PINNED_MONITORS)
    ]


def final_report(monitor_id: str, target: dict, set_sha: str) -> dict:
    statement = {
        "schema": rotation2_verify.FINAL_STATEMENT_SCHEMA,
        "monitor_id": monitor_id,
        "final_monitor_set_sequence": rotation2_verify.FINAL_SET_SEQUENCE,
        "final_monitor_set_sha256": set_sha,
        **target,
        "production": False,
    }
    return {
        "schema": rotation2_verify.FINAL_REPORT_SCHEMA,
        "algorithm": rotation2_verify.ALGORITHM,
        "statement": statement,
        "signature": base64.b64encode(
            private_for(monitor_id, rotation2_verify.FINAL_PINNED_MONITORS).sign(
                rotation2_verify.final_message(statement)
            )
        ).decode("ascii"),
    }


def final_bundle(reports: list[dict], set_sha: str) -> dict:
    return {
        "schema": rotation2_verify.FINAL_BUNDLE_SCHEMA,
        "final_monitor_set_sequence": rotation2_verify.FINAL_SET_SEQUENCE,
        "final_monitor_set_sha256": set_sha,
        "threshold": rotation2_verify.THRESHOLD,
        "reports": sorted(reports, key=lambda report: report["statement"]["monitor_id"]),
        "production": False,
    }


def main() -> None:
    if len(sys.argv) != 2 or len(sys.argv[1]) != 40 or any(
        c not in "0123456789abcdef" for c in sys.argv[1]
    ):
        raise SystemExit("usage: rust_112_multistep_rust110_checkpoint_monitor_rotation_fixture.py SOURCE_SHA")
    source_sha = sys.argv[1]

    checkpoint_raw, checkpoint = floor_verify.load_canonical(
        OUT / "axven-rust109-final-monitor-rotation-checkpoint.json",
        "RUST-109 final monitor rotation checkpoint",
    )
    first_rotation_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust111-monitor-set-rotation.json",
        "RUST-112 first monitor-set rotation",
    )
    first_auth_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust111-monitor-set-rotation-auth.json",
        "RUST-112 first monitor-set rotation authorization",
    )
    first_successor_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust111-successor-monitor-bundle.json",
        "RUST-112 first successor monitor bundle",
    )
    _, first_fork_bundle = floor_verify.load_canonical(
        OUT / "axven-rust111-successor-fork-bundle.json",
        "RUST-112 first successor fork bundle",
    )

    target = monitor_verify.checkpoint_target(checkpoint_raw, checkpoint["statement"])
    if target["activation_source_commit"] != source_sha:
        raise AssertionError("RUST-112 checkpoint source mismatch")

    rotation = {
        "schema": rotation2_verify.ROTATION_SCHEMA,
        "sequence": rotation2_verify.FINAL_SET_SEQUENCE,
        "from_set_sha256": rotation2_verify.sha256(
            material_verify.canonical(rotation1_verify.new_monitor_set())
        ),
        "to_set": rotation2_verify.final_monitor_set(),
        "cumulative_revoked_monitor_ids": rotation2_verify.CUMULATIVE_REVOKED_MONITOR_IDS,
        "predecessor_rotation_sha256": rotation2_verify.sha256(first_rotation_raw),
        "predecessor_rotation_auth_sha256": rotation2_verify.sha256(first_auth_raw),
        "predecessor_successor_bundle_sha256": rotation2_verify.sha256(first_successor_raw),
        **target,
        "production": False,
    }
    rotation_raw = material_verify.canonical(rotation)
    auth = {
        "schema": rotation2_verify.ROTATION_AUTH_SCHEMA,
        "algorithm": rotation2_verify.ALGORITHM,
        "threshold": rotation2_verify.THRESHOLD,
        "payload_type": rotation2_verify.ROTATION_PAYLOAD_TYPE,
        "payload_sha256": hashlib.sha256(rotation_raw).hexdigest(),
        "monitors": auth_rows(rotation_raw),
        "production": False,
    }

    set_sha = rotation2_verify.sha256(
        material_verify.canonical(rotation2_verify.final_monitor_set())
    )
    reports = [
        final_report(monitor_id, target, set_sha)
        for monitor_id in sorted(rotation2_verify.FINAL_PINNED_MONITORS)
    ]
    fork_statement = next(
        report["statement"]
        for report in first_fork_bundle["reports"]
        if any(report["statement"][key] != target[key] for key in monitor_verify.TARGET_KEYS)
    )
    fork_target = {
        key: copy.deepcopy(fork_statement[key]) for key in monitor_verify.TARGET_KEYS
    }
    fork_report = final_report(rotation2_verify.M5_ID, fork_target, set_sha)

    (OUT / "axven-rust112-second-monitor-set-rotation.json").write_bytes(rotation_raw)
    (OUT / "axven-rust112-second-monitor-set-rotation-auth.json").write_bytes(
        material_verify.canonical(auth)
    )
    (OUT / "axven-rust112-final-monitor-bundle.json").write_bytes(
        material_verify.canonical(final_bundle(reports, set_sha))
    )
    (OUT / "axven-rust112-final-fork-monitor-bundle.json").write_bytes(
        material_verify.canonical(final_bundle([reports[0], reports[1], fork_report], set_sha))
    )
    print("RUST-112 TEST-only second monitor-set rotation fixture: GREEN")


if __name__ == "__main__":
    main()
