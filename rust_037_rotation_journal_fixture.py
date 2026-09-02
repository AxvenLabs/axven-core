#!/usr/bin/env python3
"""RUST-037 TEST-ONLY journal/checkpoint producer. Private seeds stay outside detached consumer."""
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
import rust_035_witness_set_rotation_verify as rotation1_verify
import rust_036_multistep_witness_rotation_verify as rotation2_verify
import rust_037_rotation_journal_verify as journal_verify

SEEDS = {
    rotation1_verify.quorum_verify.WITNESS_B_KEY_ID: "11" * 32,
    rotation1_verify.quorum_verify.WITNESS_C_KEY_ID: "22" * 32,
    rotation1_verify.D_KEY_ID: "33" * 32,
    rotation2_verify.E_KEY_ID: "44" * 32,
}
OUT = Path("/tmp")


def sign_rows(ids: list[str], pins: dict[str, bytes], message: bytes) -> list[dict]:
    rows = []
    for key_id in sorted(ids):
        private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[key_id]))
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if public != pins[key_id]:
            raise AssertionError("RUST-037 TEST-only public-key pin mismatch")
        rows.append({"key_id": key_id, "signature": base64.b64encode(private.sign(message)).decode("ascii")})
    return rows


def checkpoint(journal_raw: bytes, statement: dict, pins: dict[str, bytes]) -> dict:
    return {
        "schema": journal_verify.CHECKPOINT_SCHEMA,
        "algorithm": journal_verify.ALGORITHM,
        "statement": statement,
        "witnesses": sign_rows(list(pins), pins, journal_verify.checkpoint_message(statement, journal_raw)),
    }


def main() -> None:
    if len(sys.argv) != 2 or len(sys.argv[1]) != 40 or any(c not in "0123456789abcdef" for c in sys.argv[1]):
        raise SystemExit("usage: rust_037_rotation_journal_fixture.py SOURCE_SHA")
    source_sha = sys.argv[1]
    first_rotation_raw, _ = floor_verify.load_canonical(OUT / "axven-rust036-first-rotation.json", "first rotation")
    second_rotation_raw, _ = floor_verify.load_canonical(OUT / "axven-rust036-second-rotation.json", "second rotation")
    entries = journal_verify.expected_entries(first_rotation_raw, second_rotation_raw)

    prefix_journal = journal_verify.expected_journal(entries[:2], source_sha)
    prefix_journal_raw = material_verify.canonical(prefix_journal)
    prefix_statement = journal_verify.checkpoint_statement(
        prefix_journal_raw, material_verify.canonical(entries[1]), 1,
        rotation1_verify.new_witness_set(), None, 2,
    )
    prefix_checkpoint = checkpoint(prefix_journal_raw, prefix_statement, rotation1_verify.NEW_PINNED_WITNESSES)
    prefix_checkpoint_raw = material_verify.canonical(prefix_checkpoint)

    final_journal = journal_verify.expected_journal(entries, source_sha)
    final_journal_raw = material_verify.canonical(final_journal)
    final_statement = journal_verify.checkpoint_statement(
        final_journal_raw, material_verify.canonical(entries[2]), 2,
        rotation2_verify.final_witness_set(), hashlib.sha256(prefix_checkpoint_raw).hexdigest(), 3,
    )
    final_checkpoint = checkpoint(final_journal_raw, final_statement, rotation2_verify.FINAL_PINNED_WITNESSES)

    # A deliberately conflicting, validly signed same-parent sequence-2 checkpoint used only by selftest.
    fork_statement = copy.deepcopy(final_statement)
    fork_statement["journal_sha256"] = "f" * 64
    fork_checkpoint = checkpoint(final_journal_raw, fork_statement, rotation2_verify.FINAL_PINNED_WITNESSES)

    (OUT / "axven-rust037-prefix-journal.json").write_bytes(prefix_journal_raw)
    (OUT / "axven-rust037-prefix-checkpoint.json").write_bytes(prefix_checkpoint_raw)
    (OUT / "axven-rust037-final-journal.json").write_bytes(final_journal_raw)
    (OUT / "axven-rust037-final-checkpoint.json").write_bytes(material_verify.canonical(final_checkpoint))
    (OUT / "axven-rust037-observed-fork-checkpoint.json").write_bytes(material_verify.canonical(fork_checkpoint))
    print("RUST-037 TEST-only journal/checkpoint fixture: GREEN")


if __name__ == "__main__":
    main()
