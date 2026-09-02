#!/usr/bin/env python3
"""RUST-038 TEST-ONLY observer report producer. Private seeds stay producer-side."""
from __future__ import annotations

import base64
import copy
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify
import rust_038_checkpoint_gossip_verify as gossip_verify

OUT = Path("/tmp")
SEEDS = {
    gossip_verify.OBSERVER_1_ID: "55" * 32,
    gossip_verify.OBSERVER_2_ID: "66" * 32,
    gossip_verify.OBSERVER_3_ID: "77" * 32,
}


def signed_report(observer_id: str, target: dict) -> dict:
    statement = {
        "schema": gossip_verify.STATEMENT_SCHEMA,
        "observer_id": observer_id,
        **target,
        "production": False,
    }
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[observer_id]))
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if public != gossip_verify.PINNED_OBSERVERS[observer_id]:
        raise AssertionError("RUST-038 TEST-only observer public-key pin mismatch")
    return {
        "schema": gossip_verify.REPORT_SCHEMA,
        "algorithm": gossip_verify.ALGORITHM,
        "statement": statement,
        "signature": base64.b64encode(private.sign(gossip_verify.observation_message(statement))).decode("ascii"),
    }


def bundle(reports: list[dict]) -> dict:
    reports = sorted(reports, key=lambda report: report["statement"]["observer_id"])
    return {
        "schema": gossip_verify.BUNDLE_SCHEMA,
        "threshold": gossip_verify.THRESHOLD,
        "reports": reports,
        "production": False,
    }


def main() -> None:
    if len(sys.argv) != 2 or len(sys.argv[1]) != 40 or any(c not in "0123456789abcdef" for c in sys.argv[1]):
        raise SystemExit("usage: rust_038_checkpoint_gossip_fixture.py SOURCE_SHA")
    source_sha = sys.argv[1]
    _, checkpoint = floor_verify.load_canonical(OUT / "axven-rust037-final-checkpoint.json", "final checkpoint")
    target = gossip_verify.canonical_target(checkpoint, source_sha)
    reports = [signed_report(observer_id, target) for observer_id in sorted(SEEDS)]

    fork_checkpoint_statement = copy.deepcopy(checkpoint["statement"])
    fork_checkpoint_statement["journal_sha256"] = "f" * 64
    fork_target = copy.deepcopy(target)
    fork_target["checkpoint_statement_sha256"] = gossip_verify.sha256(material_verify.canonical(fork_checkpoint_statement))
    fork_target["journal_sha256"] = fork_checkpoint_statement["journal_sha256"]
    fork_report = signed_report(gossip_verify.OBSERVER_3_ID, fork_target)

    (OUT / "axven-rust038-observer-bundle.json").write_bytes(material_verify.canonical(bundle(reports)))
    (OUT / "axven-rust038-observed-fork-bundle.json").write_bytes(
        material_verify.canonical(bundle([reports[0], reports[1], fork_report]))
    )
    print("RUST-038 TEST-only observer gossip fixture: GREEN")


if __name__ == "__main__":
    main()
