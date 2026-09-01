#!/usr/bin/env python3
"""RUST-033: TEST-ONLY signed external monotonic-floor witness consumer."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile

import rust_030_stdlib_material_verify as material_verify
import rust_032_external_monotonic_floor_verify as floor_verify

WITNESS_ENVELOPE_SCHEMA = "axven-native-external-floor-witness-envelope-v1"
WITNESS_PAYLOAD_TYPE = "application/vnd.axven.native-external-monotonic-floor.v1+json"
WITNESS_KEY_ID = "rust-033-test-only-floor-witness-v1"
WITNESS_PUBLIC_KEY = bytes.fromhex("2dc9daf238e33ee76362715bf7b37a2d3e7472b83c24242fa4d0e914f1324588")
WITNESS_DOMAIN = b"AXVEN_NATIVE_EXTERNAL_FLOOR_WITNESS_V1\x00"
ALGORITHM = "ed25519"
ENVELOPE_KEYS = frozenset({"schema", "algorithm", "key_id", "payload_type", "payload_sha256", "signature"})


def signed_message(payload: bytes) -> bytes:
    return WITNESS_DOMAIN + len(payload).to_bytes(8, "big") + payload


def validate_witness_envelope(envelope: dict, floor_raw: bytes) -> None:
    if frozenset(envelope) != ENVELOPE_KEYS:
        raise AssertionError("unexpected floor-witness envelope fields")
    if envelope.get("schema") != WITNESS_ENVELOPE_SCHEMA:
        raise AssertionError("unexpected floor-witness envelope schema")
    if envelope.get("algorithm") != ALGORITHM:
        raise AssertionError("unexpected floor-witness algorithm")
    if envelope.get("key_id") != WITNESS_KEY_ID:
        raise AssertionError("unexpected floor-witness key id")
    if envelope.get("payload_type") != WITNESS_PAYLOAD_TYPE:
        raise AssertionError("unexpected floor-witness payload type")
    if envelope.get("payload_sha256") != hashlib.sha256(floor_raw).hexdigest():
        raise AssertionError("floor-witness payload digest mismatch")
    material_verify.ed25519_verify(
        WITNESS_PUBLIC_KEY,
        material_verify.decode_signature(envelope.get("signature")),
        signed_message(floor_raw),
    )


def verify(
    final_state_path: Path,
    external_floor_path: Path,
    witness_envelope_path: Path,
    expected_source_sha: str,
    required_floor_text: str,
) -> None:
    floor_verify.verify(final_state_path, external_floor_path, expected_source_sha, required_floor_text)
    floor_raw, _ = floor_verify.load_canonical(external_floor_path, "external monotonic floor")
    _, witness = floor_verify.load_canonical(witness_envelope_path, "external floor witness envelope")
    validate_witness_envelope(witness, floor_raw)
    print(
        "RUST-033 signed external floor witness: GREEN "
        f"source={expected_source_sha} floor_sha256={hashlib.sha256(floor_raw).hexdigest()} key={WITNESS_KEY_ID}"
    )


def expect_failure(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def selftest(
    final_state_path: Path,
    external_floor_path: Path,
    witness_envelope_path: Path,
    expected_source_sha: str,
    required_floor_text: str,
) -> None:
    verify(final_state_path, external_floor_path, witness_envelope_path, expected_source_sha, required_floor_text)
    floor_raw, floor = floor_verify.load_canonical(external_floor_path, "external monotonic floor")
    _, witness = floor_verify.load_canonical(witness_envelope_path, "external floor witness envelope")
    cases = 0

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def write_obj(name: str, value: dict) -> Path:
            path = root / name
            path.write_bytes(material_verify.canonical(value))
            return path

        value = copy.deepcopy(witness)
        sig = bytearray(material_verify.decode_signature(value["signature"]))
        sig[0] ^= 1
        value["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        bad = write_obj("bad-signature.json", value)
        expect_failure("witness-signature", lambda: verify(final_state_path, external_floor_path, bad, expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(witness); value["payload_sha256"] = "0" * 64
        bad = write_obj("bad-payload-digest.json", value)
        expect_failure("witness-payload-digest", lambda: verify(final_state_path, external_floor_path, bad, expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(witness); value["key_id"] = "unknown-witness"
        bad = write_obj("bad-key-id.json", value)
        expect_failure("witness-key-id", lambda: verify(final_state_path, external_floor_path, bad, expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(witness); value["payload_type"] = "application/octet-stream"
        bad = write_obj("bad-payload-type.json", value)
        expect_failure("witness-payload-type", lambda: verify(final_state_path, external_floor_path, bad, expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(witness); value["algorithm"] = "none"
        bad = write_obj("bad-algorithm.json", value)
        expect_failure("witness-algorithm", lambda: verify(final_state_path, external_floor_path, bad, expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(witness); value["schema"] = "axven-native-external-floor-witness-envelope-v0"
        bad = write_obj("bad-schema.json", value)
        expect_failure("witness-schema", lambda: verify(final_state_path, external_floor_path, bad, expected_source_sha, required_floor_text)); cases += 1

        noncanonical = root / "noncanonical-witness.json"
        noncanonical.write_text(json.dumps(witness, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-witness", lambda: verify(final_state_path, external_floor_path, noncanonical, expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(floor); value["provider"] = "substituted-provider"
        bad_floor = write_obj("bad-floor-provider.json", value)
        expect_failure("floor-provider-substitution", lambda: verify(final_state_path, bad_floor, witness_envelope_path, expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(floor); value["sequence"] = 0
        bad_floor = write_obj("stale-floor.json", value)
        expect_failure("floor-downgrade", lambda: verify(final_state_path, bad_floor, witness_envelope_path, expected_source_sha, required_floor_text)); cases += 1

        expect_failure(
            "activation-source",
            lambda: verify(final_state_path, external_floor_path, witness_envelope_path, "0" * 40, required_floor_text),
        ); cases += 1

        mutated_floor = root / "mutated-floor.json"
        mutated_floor.write_bytes(floor_raw[:-2] + b" \n")
        expect_failure("floor-byte-mutation", lambda: verify(final_state_path, mutated_floor, witness_envelope_path, expected_source_sha, required_floor_text)); cases += 1

    if cases != 11:
        raise AssertionError(f"unexpected RUST-033 selftest case count: {cases}")
    print("RUST-033 signed external floor witness fail-closed contract: 11/11 expected cases passed")


def main() -> None:
    if len(sys.argv) != 7 or sys.argv[1] not in {"verify", "selftest"}:
        raise SystemExit(
            "usage: rust_033_external_floor_witness_verify.py verify|selftest "
            "FINAL_STATE EXTERNAL_FLOOR WITNESS_ENVELOPE EXPECTED_SOURCE_SHA REQUIRED_FLOOR"
        )
    fn = verify if sys.argv[1] == "verify" else selftest
    fn(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), sys.argv[5], sys.argv[6])


if __name__ == "__main__":
    main()
