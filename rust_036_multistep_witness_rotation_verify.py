#!/usr/bin/env python3
"""RUST-036: TEST-ONLY multi-step witness rotation and cumulative revocation consumer."""
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
import rust_035_witness_set_rotation_verify as rotation1_verify

SET_SCHEMA = rotation1_verify.SET_SCHEMA
SECOND_ROTATION_SCHEMA = "axven-native-external-floor-witness-set-rotation-v2"
SECOND_AUTH_SCHEMA = "axven-native-external-floor-witness-set-rotation-quorum-v2"
FINAL_QUORUM_SCHEMA = "axven-native-external-floor-witness-quorum-v3"
SECOND_ROTATION_PAYLOAD_TYPE = "application/vnd.axven.native-external-floor-witness-set-rotation.v2+json"
FLOOR_PAYLOAD_TYPE = rotation1_verify.FLOOR_PAYLOAD_TYPE
SECOND_ROTATION_DOMAIN = b"AXVEN_NATIVE_EXTERNAL_FLOOR_WITNESS_SET_ROTATION_V2\x00"
FINAL_QUORUM_DOMAIN = b"AXVEN_NATIVE_EXTERNAL_FLOOR_WITNESS_QUORUM_V3\x00"
ALGORITHM = "ed25519"
THRESHOLD = 2
PREDECESSOR_SET_SEQUENCE = 1
FINAL_SET_SEQUENCE = 2
E_KEY_ID = "rust-036-test-only-floor-witness-e-v1"
E_PUBLIC_KEY = bytes.fromhex("d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48")
REVOKED_A_KEY_ID = rotation1_verify.REVOKED_KEY_ID
REVOKED_B_KEY_ID = rotation1_verify.quorum_verify.WITNESS_B_KEY_ID
CUMULATIVE_REVOKED_KEY_IDS = sorted([REVOKED_A_KEY_ID, REVOKED_B_KEY_ID])
PREDECESSOR_PINNED_WITNESSES = dict(rotation1_verify.NEW_PINNED_WITNESSES)
FINAL_PINNED_WITNESSES = {
    rotation1_verify.quorum_verify.WITNESS_C_KEY_ID: rotation1_verify.quorum_verify.WITNESS_C_PUBLIC_KEY,
    rotation1_verify.D_KEY_ID: rotation1_verify.D_PUBLIC_KEY,
    E_KEY_ID: E_PUBLIC_KEY,
}
SECOND_ROTATION_KEYS = frozenset({
    "schema", "sequence", "scope", "from_set_sha256", "to_set",
    "revoked_key_ids", "predecessor_rotation_sha256", "activation_source_commit", "production",
})
AUTH_KEYS = rotation1_verify.AUTH_KEYS
FINAL_QUORUM_KEYS = rotation1_verify.SUCCESSOR_KEYS


def predecessor_witness_set() -> dict:
    return rotation1_verify.canonical_witness_set(PREDECESSOR_SET_SEQUENCE, PREDECESSOR_PINNED_WITNESSES)


def final_witness_set() -> dict:
    return rotation1_verify.canonical_witness_set(FINAL_SET_SEQUENCE, FINAL_PINNED_WITNESSES)


def second_rotation_message(payload: bytes) -> bytes:
    return SECOND_ROTATION_DOMAIN + len(payload).to_bytes(8, "big") + payload


def final_quorum_message(payload: bytes) -> bytes:
    return FINAL_QUORUM_DOMAIN + len(payload).to_bytes(8, "big") + payload


def validate_second_rotation(rotation: dict, first_rotation_raw: bytes, expected_source_sha: str) -> None:
    if frozenset(rotation) != SECOND_ROTATION_KEYS:
        raise AssertionError("unexpected second witness-set rotation fields")
    if rotation.get("schema") != SECOND_ROTATION_SCHEMA:
        raise AssertionError("unexpected second witness-set rotation schema")
    if type(rotation.get("sequence")) is not int or rotation["sequence"] != FINAL_SET_SEQUENCE:
        raise AssertionError("unexpected second witness-set rotation sequence")
    if rotation.get("scope") != FLOOR_PAYLOAD_TYPE:
        raise AssertionError("unexpected second witness-set rotation scope")
    predecessor = predecessor_witness_set()
    final_set = final_witness_set()
    if rotation.get("from_set_sha256") != hashlib.sha256(material_verify.canonical(predecessor)).hexdigest():
        raise AssertionError("second rotation predecessor set digest mismatch")
    rotation1_verify.validate_set(rotation.get("to_set"), final_set, "second successor")
    if rotation.get("revoked_key_ids") != CUMULATIVE_REVOKED_KEY_IDS:
        raise AssertionError("cumulative witness revocation mismatch")
    if rotation.get("predecessor_rotation_sha256") != hashlib.sha256(first_rotation_raw).hexdigest():
        raise AssertionError("predecessor rotation digest mismatch")
    if rotation.get("activation_source_commit") != expected_source_sha:
        raise AssertionError("second rotation activation source mismatch")
    if rotation.get("production") is not False:
        raise AssertionError("production second witness-set rotation forbidden in RUST-036")


def validate_second_authorization(auth: dict, second_rotation_raw: bytes) -> None:
    rotation1_verify.validate_signature_quorum(
        auth,
        schema=SECOND_AUTH_SCHEMA,
        payload_type=SECOND_ROTATION_PAYLOAD_TYPE,
        payload_raw=second_rotation_raw,
        pins=PREDECESSOR_PINNED_WITNESSES,
        message=second_rotation_message(second_rotation_raw),
        label="second rotation authorization",
    )


def validate_final_quorum(quorum: dict, floor_raw: bytes) -> None:
    if frozenset(quorum) != FINAL_QUORUM_KEYS:
        raise AssertionError("unexpected final witness-quorum fields")
    if quorum.get("schema") != FINAL_QUORUM_SCHEMA or quorum.get("algorithm") != ALGORITHM:
        raise AssertionError("unexpected final witness-quorum identity")
    if type(quorum.get("set_sequence")) is not int or quorum["set_sequence"] != FINAL_SET_SEQUENCE:
        raise AssertionError("unexpected final witness-set sequence")
    final_set_raw = material_verify.canonical(final_witness_set())
    if quorum.get("set_sha256") != hashlib.sha256(final_set_raw).hexdigest():
        raise AssertionError("final witness-set digest mismatch")
    if type(quorum.get("threshold")) is not int or quorum["threshold"] != THRESHOLD:
        raise AssertionError("unexpected final quorum threshold")
    if quorum.get("payload_type") != FLOOR_PAYLOAD_TYPE:
        raise AssertionError("unexpected final quorum payload type")
    if quorum.get("payload_sha256") != hashlib.sha256(floor_raw).hexdigest():
        raise AssertionError("final quorum payload digest mismatch")
    if quorum.get("production") is not False:
        raise AssertionError("production final quorum forbidden in RUST-036")
    rotation1_verify._validate_signatures(
        quorum.get("witnesses"), FINAL_PINNED_WITNESSES, final_quorum_message(floor_raw), "final quorum"
    )


def verify(
    final_state_path: Path,
    external_floor_path: Path,
    first_rotation_path: Path,
    first_auth_path: Path,
    first_quorum_path: Path,
    second_rotation_path: Path,
    second_auth_path: Path,
    final_quorum_path: Path,
    expected_source_sha: str,
    required_floor_text: str,
) -> None:
    rotation1_verify.verify(
        final_state_path, external_floor_path, first_rotation_path, first_auth_path,
        first_quorum_path, expected_source_sha, required_floor_text,
    )
    floor_raw, _ = floor_verify.load_canonical(external_floor_path, "external monotonic floor")
    first_rotation_raw, _ = floor_verify.load_canonical(first_rotation_path, "first witness-set rotation")
    second_rotation_raw, second_rotation = floor_verify.load_canonical(second_rotation_path, "second witness-set rotation")
    _, second_auth = floor_verify.load_canonical(second_auth_path, "second witness-set rotation authorization")
    _, final_quorum = floor_verify.load_canonical(final_quorum_path, "final external-floor witness quorum")
    validate_second_rotation(second_rotation, first_rotation_raw, expected_source_sha)
    validate_second_authorization(second_auth, second_rotation_raw)
    validate_final_quorum(final_quorum, floor_raw)
    keys = ",".join(item["key_id"] for item in final_quorum["witnesses"])
    print(
        "RUST-036 multi-step witness rotation: GREEN "
        f"source={expected_source_sha} sequence={FINAL_SET_SEQUENCE} revoked={','.join(CUMULATIVE_REVOKED_KEY_IDS)} final={keys}"
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
    first_rotation_path: Path,
    first_auth_path: Path,
    first_quorum_path: Path,
    second_rotation_path: Path,
    second_auth_path: Path,
    final_quorum_path: Path,
    expected_source_sha: str,
    required_floor_text: str,
) -> None:
    verify(
        final_state_path, external_floor_path, first_rotation_path, first_auth_path, first_quorum_path,
        second_rotation_path, second_auth_path, final_quorum_path, expected_source_sha, required_floor_text,
    )
    floor_raw, floor = floor_verify.load_canonical(external_floor_path, "external monotonic floor")
    first_rotation_raw, _ = floor_verify.load_canonical(first_rotation_path, "first witness-set rotation")
    second_rotation_raw, second_rotation = floor_verify.load_canonical(second_rotation_path, "second witness-set rotation")
    _, second_auth = floor_verify.load_canonical(second_auth_path, "second witness-set rotation authorization")
    _, final_quorum = floor_verify.load_canonical(final_quorum_path, "final external-floor witness quorum")
    cases = 0

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        def write_obj(name: str, value: dict) -> Path:
            path = root / name; path.write_bytes(material_verify.canonical(value)); return path

        for pair in ((0, 1), (0, 2), (1, 2)):
            value = copy.deepcopy(second_auth)
            value["witnesses"] = [copy.deepcopy(second_auth["witnesses"][i]) for i in pair]
            value["witnesses"].sort(key=lambda item: item["key_id"])
            validate_second_authorization(value, second_rotation_raw)
        print("[GREEN] RUST-036 second rotation authorization: 3/3 valid two-witness subsets accepted")

        for pair in ((0, 1), (0, 2), (1, 2)):
            value = copy.deepcopy(final_quorum)
            value["witnesses"] = [copy.deepcopy(final_quorum["witnesses"][i]) for i in pair]
            value["witnesses"].sort(key=lambda item: item["key_id"])
            validate_final_quorum(value, floor_raw)
        print("[GREEN] RUST-036 final quorum availability: 3/3 valid two-witness subsets accepted")

        value=copy.deepcopy(second_auth); value["witnesses"]=value["witnesses"][:1]
        expect_failure("second-auth-below-threshold", lambda: validate_second_authorization(value, second_rotation_raw)); cases += 1
        value=copy.deepcopy(second_auth); value["threshold"]=1
        expect_failure("second-auth-threshold-downgrade", lambda: validate_second_authorization(value, second_rotation_raw)); cases += 1
        value=copy.deepcopy(second_auth); value["witnesses"][1]["key_id"]=value["witnesses"][0]["key_id"]
        expect_failure("second-auth-duplicate-key", lambda: validate_second_authorization(value, second_rotation_raw)); cases += 1
        value=copy.deepcopy(second_auth); sig=bytearray(material_verify.decode_signature(value["witnesses"][0]["signature"])); sig[0]^=1; value["witnesses"][0]["signature"]=base64.b64encode(bytes(sig)).decode("ascii")
        expect_failure("second-auth-signature", lambda: validate_second_authorization(value, second_rotation_raw)); cases += 1
        value=copy.deepcopy(second_rotation); value["sequence"]=1
        expect_failure("second-rotation-sequence-rollback", lambda: validate_second_rotation(value, first_rotation_raw, expected_source_sha)); cases += 1
        value=copy.deepcopy(second_rotation); value["from_set_sha256"]="0"*64
        expect_failure("second-rotation-predecessor-set", lambda: validate_second_rotation(value, first_rotation_raw, expected_source_sha)); cases += 1
        value=copy.deepcopy(second_rotation); value["predecessor_rotation_sha256"]="0"*64
        expect_failure("second-rotation-predecessor-record", lambda: validate_second_rotation(value, first_rotation_raw, expected_source_sha)); cases += 1
        value=copy.deepcopy(second_rotation); value["revoked_key_ids"]=[REVOKED_A_KEY_ID]
        expect_failure("cumulative-revocation-truncation", lambda: validate_second_rotation(value, first_rotation_raw, expected_source_sha)); cases += 1
        value=copy.deepcopy(second_rotation); value["to_set"]["witnesses"][0]["key_id"]=REVOKED_B_KEY_ID
        expect_failure("second-successor-set-reintroduces-b", lambda: validate_second_rotation(value, first_rotation_raw, expected_source_sha)); cases += 1
        value=copy.deepcopy(second_rotation); value["activation_source_commit"]="0"*40
        expect_failure("second-rotation-source", lambda: validate_second_rotation(value, first_rotation_raw, expected_source_sha)); cases += 1
        value=copy.deepcopy(second_rotation); value["production"]=True
        expect_failure("second-rotation-production", lambda: validate_second_rotation(value, first_rotation_raw, expected_source_sha)); cases += 1
        value=copy.deepcopy(final_quorum); value["witnesses"]=value["witnesses"][:1]
        expect_failure("final-below-threshold", lambda: validate_final_quorum(value, floor_raw)); cases += 1
        value=copy.deepcopy(final_quorum); value["witnesses"][0]["key_id"]=REVOKED_A_KEY_ID; value["witnesses"].sort(key=lambda item:item["key_id"])
        expect_failure("final-reintroduces-a", lambda: validate_final_quorum(value, floor_raw)); cases += 1
        value=copy.deepcopy(final_quorum); value["witnesses"][0]["key_id"]=REVOKED_B_KEY_ID; value["witnesses"].sort(key=lambda item:item["key_id"])
        expect_failure("final-reintroduces-b", lambda: validate_final_quorum(value, floor_raw)); cases += 1
        value=copy.deepcopy(final_quorum); value["set_sequence"]=1
        expect_failure("final-sequence-rollback", lambda: validate_final_quorum(value, floor_raw)); cases += 1
        value=copy.deepcopy(final_quorum); value["set_sha256"]=hashlib.sha256(material_verify.canonical(predecessor_witness_set())).hexdigest()
        expect_failure("final-predecessor-set-replay", lambda: validate_final_quorum(value, floor_raw)); cases += 1
        value=copy.deepcopy(final_quorum); value["schema"]=rotation1_verify.SUCCESSOR_QUORUM_SCHEMA
        expect_failure("sequence1-quorum-format-replay", lambda: validate_final_quorum(value, floor_raw)); cases += 1
        value=copy.deepcopy(final_quorum); sig=bytearray(material_verify.decode_signature(value["witnesses"][1]["signature"])); sig[0]^=1; value["witnesses"][1]["signature"]=base64.b64encode(bytes(sig)).decode("ascii")
        expect_failure("final-signature", lambda: validate_final_quorum(value, floor_raw)); cases += 1
        value=copy.deepcopy(final_quorum); value["payload_sha256"]="0"*64
        expect_failure("final-payload-digest", lambda: validate_final_quorum(value, floor_raw)); cases += 1
        value=copy.deepcopy(final_quorum); value["production"]=True
        expect_failure("final-production", lambda: validate_final_quorum(value, floor_raw)); cases += 1

        p=root/"noncanonical-second-rotation.json"; p.write_text(json.dumps(second_rotation,indent=2)+"\n",encoding="utf-8")
        expect_failure("noncanonical-second-rotation", lambda: verify(final_state_path,external_floor_path,first_rotation_path,first_auth_path,first_quorum_path,p,second_auth_path,final_quorum_path,expected_source_sha,required_floor_text)); cases += 1
        p=root/"noncanonical-second-auth.json"; p.write_text(json.dumps(second_auth,indent=2)+"\n",encoding="utf-8")
        expect_failure("noncanonical-second-auth", lambda: verify(final_state_path,external_floor_path,first_rotation_path,first_auth_path,first_quorum_path,second_rotation_path,p,final_quorum_path,expected_source_sha,required_floor_text)); cases += 1
        p=root/"noncanonical-final.json"; p.write_text(json.dumps(final_quorum,indent=2)+"\n",encoding="utf-8")
        expect_failure("noncanonical-final-quorum", lambda: verify(final_state_path,external_floor_path,first_rotation_path,first_auth_path,first_quorum_path,second_rotation_path,second_auth_path,p,expected_source_sha,required_floor_text)); cases += 1
        value=copy.deepcopy(floor); value["sequence"]=0
        expect_failure("floor-downgrade", lambda: verify(final_state_path,write_obj("stale-floor.json",value),first_rotation_path,first_auth_path,first_quorum_path,second_rotation_path,second_auth_path,final_quorum_path,expected_source_sha,required_floor_text)); cases += 1
        expect_failure("global-source", lambda: verify(final_state_path,external_floor_path,first_rotation_path,first_auth_path,first_quorum_path,second_rotation_path,second_auth_path,final_quorum_path,"0"*40,required_floor_text)); cases += 1

    if cases != 25:
        raise AssertionError(f"unexpected RUST-036 selftest case count: {cases}")
    print("RUST-036 multi-step witness rotation fail-closed contract: 25/25 expected cases passed")


def main() -> None:
    if len(sys.argv) != 12 or sys.argv[1] not in {"verify", "selftest"}:
        raise SystemExit(
            "usage: rust_036_multistep_witness_rotation_verify.py verify|selftest FINAL_STATE EXTERNAL_FLOOR "
            "FIRST_ROTATION FIRST_AUTH FIRST_QUORUM SECOND_ROTATION SECOND_AUTH FINAL_QUORUM EXPECTED_SOURCE_SHA REQUIRED_FLOOR"
        )
    fn = verify if sys.argv[1] == "verify" else selftest
    fn(Path(sys.argv[2]),Path(sys.argv[3]),Path(sys.argv[4]),Path(sys.argv[5]),Path(sys.argv[6]),Path(sys.argv[7]),Path(sys.argv[8]),Path(sys.argv[9]),sys.argv[10],sys.argv[11])


if __name__ == "__main__":
    main()
