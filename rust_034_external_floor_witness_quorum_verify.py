#!/usr/bin/env python3
"""RUST-034: TEST-ONLY 2-of-3 external-floor witness quorum consumer."""
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
import rust_033_external_floor_witness_verify as single_verify

QUORUM_SCHEMA = "axven-native-external-floor-witness-quorum-v1"
QUORUM_PAYLOAD_TYPE = single_verify.WITNESS_PAYLOAD_TYPE
QUORUM_DOMAIN = b"AXVEN_NATIVE_EXTERNAL_FLOOR_WITNESS_QUORUM_V1\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2
WITNESS_B_KEY_ID = "rust-034-test-only-floor-witness-b-v1"
WITNESS_C_KEY_ID = "rust-034-test-only-floor-witness-c-v1"
WITNESS_B_PUBLIC_KEY = bytes.fromhex("d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737")
WITNESS_C_PUBLIC_KEY = bytes.fromhex("a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0")
PINNED_WITNESSES = {
    single_verify.WITNESS_KEY_ID: single_verify.WITNESS_PUBLIC_KEY,
    WITNESS_B_KEY_ID: WITNESS_B_PUBLIC_KEY,
    WITNESS_C_KEY_ID: WITNESS_C_PUBLIC_KEY,
}
QUORUM_KEYS = frozenset({
    "schema", "algorithm", "threshold", "payload_type",
    "payload_sha256", "witnesses", "production",
})
WITNESS_KEYS = frozenset({"key_id", "signature"})


def signed_message(payload: bytes) -> bytes:
    return QUORUM_DOMAIN + len(payload).to_bytes(8, "big") + payload


def validate_quorum(quorum: dict, floor_raw: bytes) -> None:
    if frozenset(quorum) != QUORUM_KEYS:
        raise AssertionError("unexpected witness-quorum fields")
    if quorum.get("schema") != QUORUM_SCHEMA:
        raise AssertionError("unexpected witness-quorum schema")
    if quorum.get("algorithm") != ALGORITHM:
        raise AssertionError("unexpected witness-quorum algorithm")
    if type(quorum.get("threshold")) is not int or quorum["threshold"] != THRESHOLD:
        raise AssertionError("unexpected witness-quorum threshold")
    if quorum.get("payload_type") != QUORUM_PAYLOAD_TYPE:
        raise AssertionError("unexpected witness-quorum payload type")
    if quorum.get("payload_sha256") != hashlib.sha256(floor_raw).hexdigest():
        raise AssertionError("witness-quorum payload digest mismatch")
    if quorum.get("production") is not False:
        raise AssertionError("production witness quorum forbidden in RUST-034")

    witnesses = quorum.get("witnesses")
    if not isinstance(witnesses, list) or not (THRESHOLD <= len(witnesses) <= len(PINNED_WITNESSES)):
        raise AssertionError("invalid witness-quorum size")
    if not all(isinstance(item, dict) and frozenset(item) == WITNESS_KEYS for item in witnesses):
        raise AssertionError("invalid witness-quorum entry")

    key_ids = [item["key_id"] for item in witnesses]
    if any(not isinstance(key_id, str) for key_id in key_ids):
        raise AssertionError("witness key id must be text")
    if key_ids != sorted(key_ids) or len(set(key_ids)) != len(key_ids):
        raise AssertionError("witness key ids must be unique and sorted")
    if any(key_id not in PINNED_WITNESSES for key_id in key_ids):
        raise AssertionError("unknown witness key id")

    message = signed_message(floor_raw)
    for item in witnesses:
        material_verify.ed25519_verify(
            PINNED_WITNESSES[item["key_id"]],
            material_verify.decode_signature(item["signature"]),
            message,
        )


def verify(
    final_state_path: Path,
    external_floor_path: Path,
    quorum_path: Path,
    expected_source_sha: str,
    required_floor_text: str,
) -> None:
    floor_verify.verify(final_state_path, external_floor_path, expected_source_sha, required_floor_text)
    floor_raw, _ = floor_verify.load_canonical(external_floor_path, "external monotonic floor")
    _, quorum = floor_verify.load_canonical(quorum_path, "external floor witness quorum")
    validate_quorum(quorum, floor_raw)
    keys = ",".join(item["key_id"] for item in quorum["witnesses"])
    print(
        "RUST-034 external floor witness quorum: GREEN "
        f"source={expected_source_sha} threshold={THRESHOLD} witnesses={keys}"
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
    quorum_path: Path,
    expected_source_sha: str,
    required_floor_text: str,
) -> None:
    verify(final_state_path, external_floor_path, quorum_path, expected_source_sha, required_floor_text)
    floor_raw, floor = floor_verify.load_canonical(external_floor_path, "external monotonic floor")
    _, quorum = floor_verify.load_canonical(quorum_path, "external floor witness quorum")
    cases = 0

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def write_obj(name: str, value: dict) -> Path:
            path = root / name
            path.write_bytes(material_verify.canonical(value))
            return path

        # Any valid two of the three pinned TEST witnesses must satisfy quorum.
        for idx, pair in enumerate(((0, 1), (0, 2), (1, 2)), start=1):
            value = copy.deepcopy(quorum)
            value["witnesses"] = [copy.deepcopy(quorum["witnesses"][i]) for i in pair]
            value["witnesses"].sort(key=lambda item: item["key_id"])
            verify(final_state_path, external_floor_path, write_obj(f"valid-pair-{idx}.json", value), expected_source_sha, required_floor_text)
        print("[GREEN] RUST-034 quorum availability: 3/3 valid two-witness subsets accepted")

        value = copy.deepcopy(quorum); value["witnesses"] = value["witnesses"][:1]
        expect_failure("below-threshold", lambda: verify(final_state_path, external_floor_path, write_obj("one.json", value), expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(quorum); value["threshold"] = 1
        expect_failure("threshold-downgrade", lambda: verify(final_state_path, external_floor_path, write_obj("threshold.json", value), expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(quorum); value["witnesses"][1]["key_id"] = value["witnesses"][0]["key_id"]
        expect_failure("duplicate-key", lambda: verify(final_state_path, external_floor_path, write_obj("duplicate.json", value), expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(quorum); value["witnesses"] = list(reversed(value["witnesses"]))
        expect_failure("unsorted-keys", lambda: verify(final_state_path, external_floor_path, write_obj("unsorted.json", value), expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(quorum); value["witnesses"][0]["key_id"] = "unknown-witness"
        value["witnesses"].sort(key=lambda item: item["key_id"])
        expect_failure("unknown-key", lambda: verify(final_state_path, external_floor_path, write_obj("unknown.json", value), expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(quorum)
        sig = bytearray(material_verify.decode_signature(value["witnesses"][1]["signature"])); sig[0] ^= 1
        value["witnesses"][1]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        expect_failure("signature-mutation", lambda: verify(final_state_path, external_floor_path, write_obj("signature.json", value), expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(quorum); value["payload_sha256"] = "0" * 64
        expect_failure("payload-digest", lambda: verify(final_state_path, external_floor_path, write_obj("digest.json", value), expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(quorum); value["production"] = True
        expect_failure("production-quorum", lambda: verify(final_state_path, external_floor_path, write_obj("production.json", value), expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(quorum); value["algorithm"] = "none"
        expect_failure("algorithm", lambda: verify(final_state_path, external_floor_path, write_obj("algorithm.json", value), expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(quorum); value["schema"] = "axven-native-external-floor-witness-quorum-v0"
        expect_failure("schema", lambda: verify(final_state_path, external_floor_path, write_obj("schema.json", value), expected_source_sha, required_floor_text)); cases += 1

        noncanonical = root / "noncanonical.json"
        noncanonical.write_text(json.dumps(quorum, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-quorum", lambda: verify(final_state_path, external_floor_path, noncanonical, expected_source_sha, required_floor_text)); cases += 1

        value = copy.deepcopy(floor); value["sequence"] = 0
        expect_failure("floor-downgrade", lambda: verify(final_state_path, write_obj("stale-floor.json", value), quorum_path, expected_source_sha, required_floor_text)); cases += 1

        expect_failure("activation-source", lambda: verify(final_state_path, external_floor_path, quorum_path, "0" * 40, required_floor_text)); cases += 1

    if cases != 13:
        raise AssertionError(f"unexpected RUST-034 selftest case count: {cases}")
    print("RUST-034 witness quorum fail-closed contract: 13/13 expected cases passed")


def main() -> None:
    if len(sys.argv) != 7 or sys.argv[1] not in {"verify", "selftest"}:
        raise SystemExit(
            "usage: rust_034_external_floor_witness_quorum_verify.py verify|selftest "
            "FINAL_STATE EXTERNAL_FLOOR QUORUM EXPECTED_SOURCE_SHA REQUIRED_FLOOR"
        )
    fn = verify if sys.argv[1] == "verify" else selftest
    fn(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), sys.argv[5], sys.argv[6])


if __name__ == "__main__":
    main()
