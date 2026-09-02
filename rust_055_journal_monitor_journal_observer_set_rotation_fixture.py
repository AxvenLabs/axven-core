#!/usr/bin/env python3
"""RUST-055 TEST-ONLY journal-monitor-journal observer rotation producer."""
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
import rust_054_journal_monitor_journal_gossip_verify as gossip_verify
import rust_055_journal_monitor_journal_observer_set_rotation_verify as rotation_verify

OUT = Path("/tmp")
SEEDS = {
    gossip_verify.OBSERVER_1_ID: "9b" * 32,
    gossip_verify.OBSERVER_2_ID: "ab" * 32,
    gossip_verify.OBSERVER_3_ID: "bb" * 32,
    rotation_verify.O4_ID: "cb" * 32,
}


def private_for(observer_id: str, pins: dict[str, bytes]) -> Ed25519PrivateKey:
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[observer_id]))
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if public != pins[observer_id]:
        raise AssertionError(
            "RUST-055 TEST-only journal-monitor-journal observer public-key pin mismatch"
        )
    return private


def auth_rows(rotation_raw: bytes) -> list[dict]:
    message = rotation_verify.rotation_message(rotation_raw)
    rows = []
    for observer_id in sorted(rotation_verify.OLD_PINNED_OBSERVERS):
        rows.append({
            "observer_id": observer_id,
            "signature": base64.b64encode(
                private_for(observer_id, rotation_verify.OLD_PINNED_OBSERVERS).sign(message)
            ).decode("ascii"),
        })
    return rows


def successor_report(observer_id: str, target: dict, set_sha: str) -> dict:
    statement = {
        "schema": rotation_verify.SUCCESSOR_STATEMENT_SCHEMA,
        "observer_id": observer_id,
        "observer_set_sequence": rotation_verify.NEW_SET_SEQUENCE,
        "observer_set_sha256": set_sha,
        **target,
        "production": False,
    }
    private = private_for(observer_id, rotation_verify.NEW_PINNED_OBSERVERS)
    return {
        "schema": rotation_verify.SUCCESSOR_REPORT_SCHEMA,
        "algorithm": rotation_verify.ALGORITHM,
        "statement": statement,
        "signature": base64.b64encode(
            private.sign(rotation_verify.successor_message(statement))
        ).decode("ascii"),
    }


def successor_bundle(reports: list[dict], set_sha: str) -> dict:
    return {
        "schema": rotation_verify.SUCCESSOR_BUNDLE_SCHEMA,
        "observer_set_sequence": rotation_verify.NEW_SET_SEQUENCE,
        "observer_set_sha256": set_sha,
        "threshold": rotation_verify.THRESHOLD,
        "reports": sorted(
            reports, key=lambda report: report["statement"]["observer_id"]
        ),
        "production": False,
    }


def main() -> None:
    if (
        len(sys.argv) != 2
        or len(sys.argv[1]) != 40
        or any(c not in "0123456789abcdef" for c in sys.argv[1])
    ):
        raise SystemExit(
            "usage: rust_055_journal_monitor_journal_observer_set_rotation_fixture.py SOURCE_SHA"
        )
    source_sha = sys.argv[1]
    checkpoint_raw, checkpoint = floor_verify.load_canonical(
        OUT / "axven-rust053-final-journal-monitor-checkpoint.json",
        "final journal-monitor checkpoint",
    )
    old_bundle_raw, _ = floor_verify.load_canonical(
        OUT / "axven-rust054-journal-monitor-journal-observer-bundle.json",
        "predecessor journal-monitor-journal observer bundle",
    )
    _, old_fork_bundle = floor_verify.load_canonical(
        OUT / "axven-rust054-observed-fork-bundle.json",
        "predecessor observed fork bundle",
    )
    target = gossip_verify.canonical_target(checkpoint_raw, checkpoint, source_sha)

    rotation = {
        "schema": rotation_verify.ROTATION_SCHEMA,
        "sequence": rotation_verify.NEW_SET_SEQUENCE,
        "from_set_sha256": rotation_verify.sha256(
            material_verify.canonical(rotation_verify.old_observer_set())
        ),
        "to_set": rotation_verify.new_observer_set(),
        "revoked_observer_ids": [rotation_verify.REVOKED_OBSERVER_ID],
        "predecessor_observation_bundle_sha256": rotation_verify.sha256(old_bundle_raw),
        "checkpoint_sha256": target["checkpoint_sha256"],
        "checkpoint_statement_sha256": target["checkpoint_statement_sha256"],
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
        "observers": auth_rows(rotation_raw),
        "production": False,
    }
    set_sha = rotation_verify.sha256(
        material_verify.canonical(rotation_verify.new_observer_set())
    )
    reports = [
        successor_report(observer_id, target, set_sha)
        for observer_id in sorted(rotation_verify.NEW_PINNED_OBSERVERS)
    ]

    fork_statement = next(
        report["statement"]
        for report in old_fork_bundle["reports"]
        if report["statement"]["checkpoint_sha256"] != target["checkpoint_sha256"]
    )
    fork_target = {key: copy.deepcopy(fork_statement[key]) for key in target}
    fork_report = successor_report(rotation_verify.O4_ID, fork_target, set_sha)

    (OUT / "axven-rust055-journal-monitor-journal-observer-set-rotation.json").write_bytes(
        rotation_raw
    )
    (
        OUT / "axven-rust055-journal-monitor-journal-observer-set-rotation-auth.json"
    ).write_bytes(material_verify.canonical(auth))
    (OUT / "axven-rust055-successor-observer-bundle.json").write_bytes(
        material_verify.canonical(successor_bundle(reports, set_sha))
    )
    (OUT / "axven-rust055-successor-fork-bundle.json").write_bytes(
        material_verify.canonical(
            successor_bundle([reports[0], reports[1], fork_report], set_sha)
        )
    )
    print(
        "RUST-055 TEST-only journal-monitor-journal observer set rotation fixture: GREEN"
    )


if __name__ == "__main__":
    main()
