#!/usr/bin/env python3
"""RUST-080 TEST-ONLY second RUST-077 checkpoint observer-set rotation producer."""
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
import rust_078_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_verify as observer_verify
import rust_079_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_set_rotation_verify as rotation1_verify
import rust_080_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_verify as rotation2_verify

OUT = Path("/tmp")
SEEDS = {
    observer_verify.OBSERVER_2_ID: "19" * 32,
    observer_verify.OBSERVER_3_ID: "29" * 32,
    rotation1_verify.O4_ID: "39" * 32,
    rotation2_verify.O5_ID: "49" * 32,
}


def private_for(observer_id: str, pins: dict[str, bytes]) -> Ed25519PrivateKey:
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[observer_id]))
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if public != pins[observer_id]:
        raise AssertionError("RUST-080 TEST-only observer public-key pin mismatch")
    return private


def auth_rows(rotation_raw: bytes) -> list[dict]:
    message = rotation2_verify.rotation_message(rotation_raw)
    return [
        {
            "observer_id": observer_id,
            "signature": base64.b64encode(
                private_for(observer_id, rotation2_verify.PREDECESSOR_PINNED_OBSERVERS).sign(message)
            ).decode("ascii"),
        }
        for observer_id in sorted(rotation2_verify.PREDECESSOR_PINNED_OBSERVERS)
    ]


def final_report(observer_id: str, target: dict, set_sha: str) -> dict:
    statement = {
        "schema": rotation2_verify.FINAL_STATEMENT_SCHEMA,
        "observer_id": observer_id,
        "observer_set_sequence": rotation2_verify.FINAL_SET_SEQUENCE,
        "observer_set_sha256": set_sha,
        **target,
        "production": False,
    }
    private = private_for(observer_id, rotation2_verify.FINAL_PINNED_OBSERVERS)
    return {
        "schema": rotation2_verify.FINAL_REPORT_SCHEMA,
        "algorithm": rotation2_verify.ALGORITHM,
        "statement": statement,
        "signature": base64.b64encode(
            private.sign(rotation2_verify.final_message(statement))
        ).decode("ascii"),
    }


def final_bundle(reports: list[dict], set_sha: str) -> dict:
    return {
        "schema": rotation2_verify.FINAL_BUNDLE_SCHEMA,
        "observer_set_sequence": rotation2_verify.FINAL_SET_SEQUENCE,
        "observer_set_sha256": set_sha,
        "threshold": rotation2_verify.THRESHOLD,
        "reports": sorted(reports, key=lambda report: report["statement"]["observer_id"]),
        "production": False,
    }


def main() -> None:
    if len(sys.argv) != 2 or len(sys.argv[1]) != 40 or any(
        c not in "0123456789abcdef" for c in sys.argv[1]
    ):
        raise SystemExit(
            "usage: rust_080_multistep_monitor_rotation_journal_observer_rotation_journal_monitor_rotation_journal_observer_rotation_fixture.py SOURCE_SHA"
        )
    source_sha = sys.argv[1]

    checkpoint_raw, checkpoint = floor_verify.load_canonical(
        OUT / "axven-rust077-final-monitor-rotation-checkpoint.json",
        "RUST-077 final monitor rotation checkpoint",
    )
    first_rotation_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust079-observer-set-rotation.json", "RUST-080 first observer rotation"
    )
    first_auth_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust079-observer-set-rotation-auth.json", "RUST-080 first rotation authorization"
    )
    first_successor_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust079-successor-observer-bundle.json", "RUST-080 first successor bundle"
    )
    _, predecessor_fork_bundle = floor_verify.load_canonical(
        OUT / "axven-rust079-successor-fork-observer-bundle.json", "RUST-080 predecessor fork bundle"
    )
    target = observer_verify.canonical_target(checkpoint_raw, checkpoint, source_sha)

    rotation = {
        "schema": rotation2_verify.ROTATION_SCHEMA,
        "sequence": rotation2_verify.FINAL_SET_SEQUENCE,
        "from_set_sha256": rotation2_verify.sha256(material_verify.canonical(rotation1_verify.new_observer_set())),
        "to_set": rotation2_verify.final_observer_set(),
        "cumulative_revoked_observer_ids": rotation2_verify.CUMULATIVE_REVOKED_OBSERVER_IDS,
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
        "observers": auth_rows(rotation_raw),
        "production": False,
    }
    set_sha = rotation2_verify.sha256(material_verify.canonical(rotation2_verify.final_observer_set()))
    reports = [
        final_report(observer_id, target, set_sha)
        for observer_id in sorted(rotation2_verify.FINAL_PINNED_OBSERVERS)
    ]
    fork_statement = next(
        report["statement"] for report in predecessor_fork_bundle["reports"]
        if any(report["statement"][key] != target[key] for key in observer_verify.TARGET_KEYS)
    )
    fork_target = {key: copy.deepcopy(fork_statement[key]) for key in observer_verify.TARGET_KEYS}
    fork_report = final_report(rotation2_verify.O5_ID, fork_target, set_sha)

    (OUT / "axven-rust080-second-observer-set-rotation.json").write_bytes(rotation_raw)
    (OUT / "axven-rust080-second-observer-set-rotation-auth.json").write_bytes(material_verify.canonical(auth))
    (OUT / "axven-rust080-final-observer-bundle.json").write_bytes(material_verify.canonical(final_bundle(reports, set_sha)))
    (OUT / "axven-rust080-final-fork-observer-bundle.json").write_bytes(
        material_verify.canonical(final_bundle([reports[0], reports[1], fork_report], set_sha))
    )
    print("RUST-080 TEST-only second RUST-077 checkpoint observer-set rotation fixture: GREEN")


if __name__ == "__main__":
    main()
