#!/usr/bin/env python3
"""RUST-040 TEST-ONLY second observer-set rotation producer. Private seeds remain producer-side."""
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
import rust_038_checkpoint_gossip_verify as gossip_verify
import rust_039_observer_set_rotation_verify as rotation1_verify
import rust_040_multistep_observer_rotation_verify as rotation2_verify

OUT = Path("/tmp")
SEEDS = {
    gossip_verify.OBSERVER_2_ID: "66" * 32,
    gossip_verify.OBSERVER_3_ID: "77" * 32,
    rotation1_verify.O4_ID: "88" * 32,
    rotation2_verify.O5_ID: "99" * 32,
}


def private_for(observer_id: str, pins: dict[str, bytes]) -> Ed25519PrivateKey:
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[observer_id]))
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if public != pins[observer_id]:
        raise AssertionError("RUST-040 TEST-only observer public-key pin mismatch")
    return private


def auth_rows(rotation_raw: bytes) -> list[dict]:
    message = rotation2_verify.rotation_message(rotation_raw)
    rows = []
    for observer_id in sorted(rotation2_verify.PREDECESSOR_PINNED_OBSERVERS):
        private = private_for(observer_id, rotation2_verify.PREDECESSOR_PINNED_OBSERVERS)
        rows.append({
            "observer_id": observer_id,
            "signature": base64.b64encode(private.sign(message)).decode("ascii"),
        })
    return rows


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
        "signature": base64.b64encode(private.sign(rotation2_verify.final_message(statement))).decode("ascii"),
    }


def main() -> None:
    if len(sys.argv) != 2 or len(sys.argv[1]) != 40 or any(c not in "0123456789abcdef" for c in sys.argv[1]):
        raise SystemExit("usage: rust_040_multistep_observer_rotation_fixture.py SOURCE_SHA")
    source_sha = sys.argv[1]
    _, checkpoint = floor_verify.load_canonical(OUT / "axven-rust037-final-checkpoint.json", "final checkpoint")
    target = gossip_verify.canonical_target(checkpoint, source_sha)
    first_rotation_raw, _ = floor_verify.load_canonical(OUT / "axven-rust039-observer-set-rotation.json", "first observer rotation")
    first_successor_raw, _ = floor_verify.load_canonical(OUT / "axven-rust039-successor-observer-bundle.json", "first observer successor")
    rotation = {
        "schema": rotation2_verify.ROTATION_SCHEMA,
        "sequence": rotation2_verify.FINAL_SET_SEQUENCE,
        "from_set_sha256": rotation2_verify.sha256(material_verify.canonical(rotation1_verify.new_observer_set())),
        "to_set": rotation2_verify.final_observer_set(),
        "cumulative_revoked_observer_ids": rotation2_verify.CUMULATIVE_REVOKED_OBSERVER_IDS,
        "predecessor_rotation_sha256": hashlib.sha256(first_rotation_raw).hexdigest(),
        "predecessor_successor_bundle_sha256": hashlib.sha256(first_successor_raw).hexdigest(),
        "checkpoint_statement_sha256": target["checkpoint_statement_sha256"],
        "activation_source_commit": source_sha,
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
    reports = [final_report(observer_id, target, set_sha) for observer_id in sorted(rotation2_verify.FINAL_PINNED_OBSERVERS)]
    final_bundle = {
        "schema": rotation2_verify.FINAL_BUNDLE_SCHEMA,
        "observer_set_sequence": rotation2_verify.FINAL_SET_SEQUENCE,
        "observer_set_sha256": set_sha,
        "threshold": rotation2_verify.THRESHOLD,
        "reports": reports,
        "production": False,
    }
    fork_target = copy.deepcopy(target)
    fork_target["checkpoint_statement_sha256"] = "f" * 64
    fork_target["journal_sha256"] = "f" * 64
    fork_report = final_report(rotation2_verify.O5_ID, fork_target, set_sha)
    fork_bundle = {
        "schema": rotation2_verify.FINAL_BUNDLE_SCHEMA,
        "observer_set_sequence": rotation2_verify.FINAL_SET_SEQUENCE,
        "observer_set_sha256": set_sha,
        "threshold": rotation2_verify.THRESHOLD,
        "reports": sorted([reports[0], reports[1], fork_report], key=lambda report: report["statement"]["observer_id"]),
        "production": False,
    }
    (OUT / "axven-rust040-second-observer-set-rotation.json").write_bytes(rotation_raw)
    (OUT / "axven-rust040-second-observer-set-rotation-auth.json").write_bytes(material_verify.canonical(auth))
    (OUT / "axven-rust040-final-observer-bundle.json").write_bytes(material_verify.canonical(final_bundle))
    (OUT / "axven-rust040-final-fork-bundle.json").write_bytes(material_verify.canonical(fork_bundle))
    print("RUST-040 TEST-only second observer-set rotation fixture: GREEN")


if __name__ == "__main__":
    main()
