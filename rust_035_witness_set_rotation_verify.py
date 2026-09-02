#!/usr/bin/env python3
"""RUST-035: TEST-ONLY witness-set rotation and revocation continuity consumer."""
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
import rust_034_external_floor_witness_quorum_verify as quorum_verify

SET_SCHEMA = "axven-native-external-floor-witness-set-v1"
ROTATION_SCHEMA = "axven-native-external-floor-witness-set-rotation-v1"
ROTATION_AUTH_SCHEMA = "axven-native-external-floor-witness-set-rotation-quorum-v1"
SUCCESSOR_QUORUM_SCHEMA = "axven-native-external-floor-witness-quorum-v2"
ROTATION_PAYLOAD_TYPE = "application/vnd.axven.native-external-floor-witness-set-rotation.v1+json"
FLOOR_PAYLOAD_TYPE = quorum_verify.QUORUM_PAYLOAD_TYPE
ROTATION_DOMAIN = b"AXVEN_NATIVE_EXTERNAL_FLOOR_WITNESS_SET_ROTATION_V1\x00"
SUCCESSOR_DOMAIN = b"AXVEN_NATIVE_EXTERNAL_FLOOR_WITNESS_QUORUM_V2\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2
OLD_SET_SEQUENCE = 0
NEW_SET_SEQUENCE = 1
D_KEY_ID = "rust-035-test-only-floor-witness-d-v1"
D_PUBLIC_KEY = bytes.fromhex("17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce")
REVOKED_KEY_ID = quorum_verify.single_verify.WITNESS_KEY_ID
OLD_PINNED_WITNESSES = dict(quorum_verify.PINNED_WITNESSES)
NEW_PINNED_WITNESSES = {
    quorum_verify.WITNESS_B_KEY_ID: quorum_verify.WITNESS_B_PUBLIC_KEY,
    quorum_verify.WITNESS_C_KEY_ID: quorum_verify.WITNESS_C_PUBLIC_KEY,
    D_KEY_ID: D_PUBLIC_KEY,
}
SET_KEYS = frozenset({"schema", "sequence", "threshold", "witnesses", "production"})
SET_WITNESS_KEYS = frozenset({"key_id", "public_key"})
ROTATION_KEYS = frozenset({
    "schema", "sequence", "scope", "from_set_sha256", "to_set",
    "revoked_key_ids", "activation_source_commit", "production",
})
AUTH_KEYS = frozenset({
    "schema", "algorithm", "threshold", "payload_type",
    "payload_sha256", "witnesses", "production",
})
SUCCESSOR_KEYS = frozenset({
    "schema", "algorithm", "set_sequence", "set_sha256", "threshold",
    "payload_type", "payload_sha256", "witnesses", "production",
})
SIGNATURE_KEYS = frozenset({"key_id", "signature"})


def canonical_witness_set(sequence: int, pins: dict[str, bytes]) -> dict:
    return {
        "schema": SET_SCHEMA,
        "sequence": sequence,
        "threshold": THRESHOLD,
        "witnesses": [
            {"key_id": key_id, "public_key": pins[key_id].hex()}
            for key_id in sorted(pins)
        ],
        "production": False,
    }


def old_witness_set() -> dict:
    return canonical_witness_set(OLD_SET_SEQUENCE, OLD_PINNED_WITNESSES)


def new_witness_set() -> dict:
    return canonical_witness_set(NEW_SET_SEQUENCE, NEW_PINNED_WITNESSES)


def rotation_message(payload: bytes) -> bytes:
    return ROTATION_DOMAIN + len(payload).to_bytes(8, "big") + payload


def successor_message(payload: bytes) -> bytes:
    return SUCCESSOR_DOMAIN + len(payload).to_bytes(8, "big") + payload


def validate_set(value: object, expected: dict, label: str) -> None:
    if not isinstance(value, dict) or frozenset(value) != SET_KEYS or value != expected:
        raise AssertionError(f"unexpected {label} witness set")
    witnesses = value["witnesses"]
    if not isinstance(witnesses, list) or len(witnesses) != 3:
        raise AssertionError(f"invalid {label} witness-set size")
    if not all(isinstance(item, dict) and frozenset(item) == SET_WITNESS_KEYS for item in witnesses):
        raise AssertionError(f"invalid {label} witness-set entry")


def validate_signature_quorum(
    value: dict,
    *,
    schema: str,
    payload_type: str,
    payload_raw: bytes,
    pins: dict[str, bytes],
    message: bytes,
    label: str,
) -> None:
    if frozenset(value) != AUTH_KEYS:
        raise AssertionError(f"unexpected {label} quorum fields")
    if value.get("schema") != schema or value.get("algorithm") != ALGORITHM:
        raise AssertionError(f"unexpected {label} quorum identity")
    if type(value.get("threshold")) is not int or value["threshold"] != THRESHOLD:
        raise AssertionError(f"unexpected {label} quorum threshold")
    if value.get("payload_type") != payload_type:
        raise AssertionError(f"unexpected {label} payload type")
    if value.get("payload_sha256") != hashlib.sha256(payload_raw).hexdigest():
        raise AssertionError(f"{label} payload digest mismatch")
    if value.get("production") is not False:
        raise AssertionError(f"production {label} quorum forbidden in RUST-035")
    _validate_signatures(value.get("witnesses"), pins, message, label)


def _validate_signatures(items: object, pins: dict[str, bytes], message: bytes, label: str) -> None:
    if not isinstance(items, list) or not (THRESHOLD <= len(items) <= len(pins)):
        raise AssertionError(f"invalid {label} witness count")
    if not all(isinstance(item, dict) and frozenset(item) == SIGNATURE_KEYS for item in items):
        raise AssertionError(f"invalid {label} witness entry")
    key_ids = [item["key_id"] for item in items]
    if any(not isinstance(key_id, str) for key_id in key_ids):
        raise AssertionError(f"{label} witness key id must be text")
    if key_ids != sorted(key_ids) or len(set(key_ids)) != len(key_ids):
        raise AssertionError(f"{label} witness key ids must be unique and sorted")
    if any(key_id not in pins for key_id in key_ids):
        raise AssertionError(f"unknown {label} witness key id")
    for item in items:
        material_verify.ed25519_verify(
            pins[item["key_id"]],
            material_verify.decode_signature(item["signature"]),
            message,
        )


def validate_rotation(rotation: dict, expected_source_sha: str) -> None:
    if frozenset(rotation) != ROTATION_KEYS:
        raise AssertionError("unexpected witness-set rotation fields")
    if rotation.get("schema") != ROTATION_SCHEMA:
        raise AssertionError("unexpected witness-set rotation schema")
    if type(rotation.get("sequence")) is not int or rotation["sequence"] != NEW_SET_SEQUENCE:
        raise AssertionError("unexpected witness-set rotation sequence")
    if rotation.get("scope") != FLOOR_PAYLOAD_TYPE:
        raise AssertionError("unexpected witness-set rotation scope")
    old_set = old_witness_set()
    new_set = new_witness_set()
    if rotation.get("from_set_sha256") != hashlib.sha256(material_verify.canonical(old_set)).hexdigest():
        raise AssertionError("witness-set predecessor digest mismatch")
    validate_set(rotation.get("to_set"), new_set, "successor")
    if rotation.get("revoked_key_ids") != [REVOKED_KEY_ID]:
        raise AssertionError("unexpected witness revocation set")
    if rotation.get("activation_source_commit") != expected_source_sha:
        raise AssertionError("witness-set activation source mismatch")
    if rotation.get("production") is not False:
        raise AssertionError("production witness-set rotation forbidden in RUST-035")


def validate_rotation_authorization(auth: dict, rotation_raw: bytes) -> None:
    validate_signature_quorum(
        auth,
        schema=ROTATION_AUTH_SCHEMA,
        payload_type=ROTATION_PAYLOAD_TYPE,
        payload_raw=rotation_raw,
        pins=OLD_PINNED_WITNESSES,
        message=rotation_message(rotation_raw),
        label="rotation authorization",
    )


def validate_successor_quorum(successor: dict, floor_raw: bytes) -> None:
    if frozenset(successor) != SUCCESSOR_KEYS:
        raise AssertionError("unexpected successor witness-quorum fields")
    if successor.get("schema") != SUCCESSOR_QUORUM_SCHEMA or successor.get("algorithm") != ALGORITHM:
        raise AssertionError("unexpected successor witness-quorum identity")
    if type(successor.get("set_sequence")) is not int or successor["set_sequence"] != NEW_SET_SEQUENCE:
        raise AssertionError("unexpected successor witness-set sequence")
    new_set_raw = material_verify.canonical(new_witness_set())
    if successor.get("set_sha256") != hashlib.sha256(new_set_raw).hexdigest():
        raise AssertionError("successor witness-set digest mismatch")
    if type(successor.get("threshold")) is not int or successor["threshold"] != THRESHOLD:
        raise AssertionError("unexpected successor quorum threshold")
    if successor.get("payload_type") != FLOOR_PAYLOAD_TYPE:
        raise AssertionError("unexpected successor quorum payload type")
    if successor.get("payload_sha256") != hashlib.sha256(floor_raw).hexdigest():
        raise AssertionError("successor quorum payload digest mismatch")
    if successor.get("production") is not False:
        raise AssertionError("production successor quorum forbidden in RUST-035")
    _validate_signatures(
        successor.get("witnesses"),
        NEW_PINNED_WITNESSES,
        successor_message(floor_raw),
        "successor quorum",
    )


def verify(
    final_state_path: Path,
    external_floor_path: Path,
    rotation_path: Path,
    rotation_auth_path: Path,
    successor_quorum_path: Path,
    expected_source_sha: str,
    required_floor_text: str,
) -> None:
    floor_verify.verify(final_state_path, external_floor_path, expected_source_sha, required_floor_text)
    floor_raw, _ = floor_verify.load_canonical(external_floor_path, "external monotonic floor")
    rotation_raw, rotation = floor_verify.load_canonical(rotation_path, "witness-set rotation")
    _, auth = floor_verify.load_canonical(rotation_auth_path, "witness-set rotation authorization")
    _, successor = floor_verify.load_canonical(successor_quorum_path, "successor external-floor witness quorum")
    validate_rotation(rotation, expected_source_sha)
    validate_rotation_authorization(auth, rotation_raw)
    validate_successor_quorum(successor, floor_raw)
    keys = ",".join(item["key_id"] for item in successor["witnesses"])
    print(
        "RUST-035 witness-set rotation continuity: GREEN "
        f"source={expected_source_sha} revoked={REVOKED_KEY_ID} successor={keys}"
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
    rotation_path: Path,
    rotation_auth_path: Path,
    successor_quorum_path: Path,
    expected_source_sha: str,
    required_floor_text: str,
) -> None:
    verify(
        final_state_path, external_floor_path, rotation_path, rotation_auth_path,
        successor_quorum_path, expected_source_sha, required_floor_text,
    )
    floor_raw, floor = floor_verify.load_canonical(external_floor_path, "external monotonic floor")
    rotation_raw, rotation = floor_verify.load_canonical(rotation_path, "witness-set rotation")
    _, auth = floor_verify.load_canonical(rotation_auth_path, "witness-set rotation authorization")
    _, successor = floor_verify.load_canonical(successor_quorum_path, "successor external-floor witness quorum")
    cases = 0

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def write_obj(name: str, value: dict) -> Path:
            path = root / name
            path.write_bytes(material_verify.canonical(value))
            return path

        for pair in ((0, 1), (0, 2), (1, 2)):
            value = copy.deepcopy(auth)
            value["witnesses"] = [copy.deepcopy(auth["witnesses"][i]) for i in pair]
            value["witnesses"].sort(key=lambda item: item["key_id"])
            validate_rotation_authorization(value, rotation_raw)
        print("[GREEN] RUST-035 predecessor rotation authorization: 3/3 valid two-witness subsets accepted")

        for pair in ((0, 1), (0, 2), (1, 2)):
            value = copy.deepcopy(successor)
            value["witnesses"] = [copy.deepcopy(successor["witnesses"][i]) for i in pair]
            value["witnesses"].sort(key=lambda item: item["key_id"])
            validate_successor_quorum(value, floor_raw)
        print("[GREEN] RUST-035 successor quorum availability: 3/3 valid two-witness subsets accepted")

        value = copy.deepcopy(auth); value["witnesses"] = value["witnesses"][:1]
        expect_failure("rotation-below-threshold", lambda: validate_rotation_authorization(value, rotation_raw)); cases += 1
        value = copy.deepcopy(auth); value["threshold"] = 1
        expect_failure("rotation-threshold-downgrade", lambda: validate_rotation_authorization(value, rotation_raw)); cases += 1
        value = copy.deepcopy(auth); value["witnesses"][1]["key_id"] = value["witnesses"][0]["key_id"]
        expect_failure("rotation-duplicate-key", lambda: validate_rotation_authorization(value, rotation_raw)); cases += 1
        value = copy.deepcopy(auth)
        sig = bytearray(material_verify.decode_signature(value["witnesses"][0]["signature"])); sig[0] ^= 1
        value["witnesses"][0]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        expect_failure("rotation-signature-mutation", lambda: validate_rotation_authorization(value, rotation_raw)); cases += 1
        value = copy.deepcopy(rotation); value["from_set_sha256"] = "0" * 64
        expect_failure("rotation-predecessor-digest", lambda: validate_rotation(value, expected_source_sha)); cases += 1
        value = copy.deepcopy(rotation); value["to_set"]["threshold"] = 1
        expect_failure("rotation-successor-set-substitution", lambda: validate_rotation(value, expected_source_sha)); cases += 1
        value = copy.deepcopy(rotation); value["revoked_key_ids"] = []
        expect_failure("rotation-revocation-removal", lambda: validate_rotation(value, expected_source_sha)); cases += 1
        value = copy.deepcopy(rotation); value["activation_source_commit"] = "0" * 40
        expect_failure("rotation-activation-source", lambda: validate_rotation(value, expected_source_sha)); cases += 1
        value = copy.deepcopy(rotation); value["production"] = True
        expect_failure("rotation-production", lambda: validate_rotation(value, expected_source_sha)); cases += 1
        value = copy.deepcopy(successor); value["witnesses"] = value["witnesses"][:1]
        expect_failure("successor-below-threshold", lambda: validate_successor_quorum(value, floor_raw)); cases += 1
        value = copy.deepcopy(successor)
        value["witnesses"][0]["key_id"] = REVOKED_KEY_ID
        value["witnesses"].sort(key=lambda item: item["key_id"])
        expect_failure("revoked-witness-replay", lambda: validate_successor_quorum(value, floor_raw)); cases += 1
        value = copy.deepcopy(successor); value["set_sequence"] = OLD_SET_SEQUENCE
        expect_failure("successor-set-sequence-rollback", lambda: validate_successor_quorum(value, floor_raw)); cases += 1
        value = copy.deepcopy(successor)
        value["set_sha256"] = hashlib.sha256(material_verify.canonical(old_witness_set())).hexdigest()
        expect_failure("successor-old-set-digest", lambda: validate_successor_quorum(value, floor_raw)); cases += 1
        value = copy.deepcopy(successor)
        sig = bytearray(material_verify.decode_signature(value["witnesses"][1]["signature"])); sig[0] ^= 1
        value["witnesses"][1]["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        expect_failure("successor-signature-mutation", lambda: validate_successor_quorum(value, floor_raw)); cases += 1
        value = copy.deepcopy(successor); value["payload_sha256"] = "0" * 64
        expect_failure("successor-payload-digest", lambda: validate_successor_quorum(value, floor_raw)); cases += 1
        value = copy.deepcopy(successor); value["schema"] = quorum_verify.QUORUM_SCHEMA
        expect_failure("old-quorum-format-replay", lambda: validate_successor_quorum(value, floor_raw)); cases += 1
        value = copy.deepcopy(successor); value["production"] = True
        expect_failure("successor-production", lambda: validate_successor_quorum(value, floor_raw)); cases += 1

        noncanonical_rotation = root / "noncanonical-rotation.json"
        noncanonical_rotation.write_text(json.dumps(rotation, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-rotation", lambda: verify(final_state_path, external_floor_path, noncanonical_rotation, rotation_auth_path, successor_quorum_path, expected_source_sha, required_floor_text)); cases += 1
        noncanonical_auth = root / "noncanonical-auth.json"
        noncanonical_auth.write_text(json.dumps(auth, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-rotation-auth", lambda: verify(final_state_path, external_floor_path, rotation_path, noncanonical_auth, successor_quorum_path, expected_source_sha, required_floor_text)); cases += 1
        noncanonical_successor = root / "noncanonical-successor.json"
        noncanonical_successor.write_text(json.dumps(successor, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-successor-quorum", lambda: verify(final_state_path, external_floor_path, rotation_path, rotation_auth_path, noncanonical_successor, expected_source_sha, required_floor_text)); cases += 1
        value = copy.deepcopy(floor); value["sequence"] = 0
        expect_failure("floor-downgrade", lambda: verify(final_state_path, write_obj("stale-floor.json", value), rotation_path, rotation_auth_path, successor_quorum_path, expected_source_sha, required_floor_text)); cases += 1
        expect_failure("global-activation-source", lambda: verify(final_state_path, external_floor_path, rotation_path, rotation_auth_path, successor_quorum_path, "0" * 40, required_floor_text)); cases += 1

    if cases != 22:
        raise AssertionError(f"unexpected RUST-035 selftest case count: {cases}")
    print("RUST-035 witness-set rotation fail-closed contract: 22/22 expected cases passed")


def main() -> None:
    if len(sys.argv) != 9 or sys.argv[1] not in {"verify", "selftest"}:
        raise SystemExit(
            "usage: rust_035_witness_set_rotation_verify.py verify|selftest "
            "FINAL_STATE EXTERNAL_FLOOR ROTATION ROTATION_AUTH SUCCESSOR_QUORUM "
            "EXPECTED_SOURCE_SHA REQUIRED_FLOOR"
        )
    fn = verify if sys.argv[1] == "verify" else selftest
    fn(
        Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]),
        Path(sys.argv[6]), sys.argv[7], sys.argv[8],
    )


if __name__ == "__main__":
    main()
