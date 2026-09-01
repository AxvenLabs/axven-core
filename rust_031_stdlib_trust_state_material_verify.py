#!/usr/bin/env python3
"""RUST-031: stdlib-only successor material verification behind a monotonic trust-state floor."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile

import rust_030_stdlib_material_verify as material_verify

STATE_SCHEMA = "axven-native-trust-state-v1"
TRANSITION_SCHEMA = "axven-native-trust-transition-v1"
TRANSITION_ENVELOPE_SCHEMA = "axven-native-trust-transition-envelope-v1"
TRANSITION_PAYLOAD_TYPE = "application/vnd.axven.native-trust-transition.v1+json"
TRANSITION_DOMAIN = b"AXVEN_NATIVE_TRUST_TRANSITION_V1\x00"
MATERIAL_PAYLOAD_TYPE = material_verify.PAYLOAD_TYPE
MATERIAL_ENVELOPE_SCHEMA = material_verify.ENVELOPE_SCHEMA
MATERIAL_DOMAIN = material_verify.DOMAIN
ALGORITHM = "ed25519"
OLD_KEY_ID = "rust-026-test-only-ed25519-v1"
OLD_PUBLIC_KEY = bytes.fromhex("4dd000548d1ed66588e6c23531163bd12c9c5dbca5eb932d4c6a75cde6525064")
NEW_KEY_ID = "rust-028-test-only-ed25519-v2"
NEW_PUBLIC_KEY = bytes.fromhex("158d55a155c9191d0783d48c1a1a1531fe65a783356c5b221e6952e57d58fdb3")
MINIMUM_SEQUENCE = 1
REPOSITORY = "AxvenLabs/axven-core"
HEX = frozenset("0123456789abcdef")
STATE_KEYS = frozenset({"schema", "sequence", "scope", "key_id", "public_key", "activation_source_commit", "predecessor_sha256", "transition_sha256", "production"})
TRANSITION_KEYS = frozenset({"schema", "sequence", "scope", "from_key_id", "from_public_key", "to_key_id", "to_public_key", "activation_source_commit", "production"})
ENVELOPE_KEYS = frozenset({"schema", "algorithm", "key_id", "payload_type", "payload_sha256", "signature"})


def lower_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(ch in HEX for ch in value)


def signed_message(domain: bytes, payload: bytes) -> bytes:
    return domain + len(payload).to_bytes(8, "big") + payload


def verify_ed25519(public_key: bytes, signature: object, domain: bytes, payload: bytes, label: str) -> None:
    try:
        material_verify.ed25519_verify(public_key, material_verify.decode_signature(signature), signed_message(domain, payload))
    except AssertionError as exc:
        raise AssertionError(f"{label} signature mismatch") from exc


def validate_materials(raw: bytes, value: dict, expected_source_sha: str) -> str:
    if value.get("schema") != material_verify.SCHEMA:
        raise AssertionError("unexpected materials schema")
    source = value.get("source")
    if not isinstance(source, dict) or set(source) != {"repository", "commit"}:
        raise AssertionError("unexpected materials source identity")
    if source["repository"] != REPOSITORY:
        raise AssertionError("unexpected materials repository")
    if source["commit"] != expected_source_sha or not lower_hex(expected_source_sha, 40):
        raise AssertionError("materials source commit mismatch")
    return hashlib.sha256(raw).hexdigest()


def validate_material_envelope(envelope: dict, expected_key_id: str, payload_sha256: str) -> None:
    if frozenset(envelope) != ENVELOPE_KEYS:
        raise AssertionError("unexpected material envelope fields")
    if envelope["schema"] != MATERIAL_ENVELOPE_SCHEMA or envelope["algorithm"] != ALGORITHM:
        raise AssertionError("unexpected material envelope schema/algorithm")
    if envelope["key_id"] != expected_key_id or envelope["payload_type"] != MATERIAL_PAYLOAD_TYPE:
        raise AssertionError("unexpected material envelope trust identity")
    if envelope["payload_sha256"] != payload_sha256:
        raise AssertionError("material payload SHA-256 mismatch")


def validate_genesis(raw: bytes, value: dict) -> None:
    if raw != material_verify.canonical(value) or frozenset(value) != STATE_KEYS or value["schema"] != STATE_SCHEMA:
        raise AssertionError("invalid genesis trust-state encoding/schema")
    expected = {
        "schema": STATE_SCHEMA,
        "sequence": 0,
        "scope": MATERIAL_PAYLOAD_TYPE,
        "key_id": OLD_KEY_ID,
        "public_key": OLD_PUBLIC_KEY.hex(),
        "activation_source_commit": None,
        "predecessor_sha256": None,
        "transition_sha256": None,
        "production": False,
    }
    if value != expected:
        raise AssertionError("genesis trust root mismatch")


def validate_transition(raw: bytes, value: dict, envelope: dict, expected_source_sha: str) -> None:
    if raw != material_verify.canonical(value) or frozenset(value) != TRANSITION_KEYS or value["schema"] != TRANSITION_SCHEMA:
        raise AssertionError("invalid trust-transition encoding/schema")
    expected = {
        "schema": TRANSITION_SCHEMA,
        "sequence": 1,
        "scope": MATERIAL_PAYLOAD_TYPE,
        "from_key_id": OLD_KEY_ID,
        "from_public_key": OLD_PUBLIC_KEY.hex(),
        "to_key_id": NEW_KEY_ID,
        "to_public_key": NEW_PUBLIC_KEY.hex(),
        "activation_source_commit": expected_source_sha,
        "production": False,
    }
    if value != expected or not lower_hex(expected_source_sha, 40):
        raise AssertionError("unexpected TEST-ONLY trust transition")
    if OLD_PUBLIC_KEY == NEW_PUBLIC_KEY:
        raise AssertionError("old/new trust roots must be distinct")
    if frozenset(envelope) != ENVELOPE_KEYS:
        raise AssertionError("unexpected transition-envelope fields")
    if envelope["schema"] != TRANSITION_ENVELOPE_SCHEMA or envelope["algorithm"] != ALGORITHM:
        raise AssertionError("unexpected transition-envelope schema/algorithm")
    if envelope["key_id"] != OLD_KEY_ID or envelope["payload_type"] != TRANSITION_PAYLOAD_TYPE:
        raise AssertionError("unexpected transition-envelope trust identity")
    if envelope["payload_sha256"] != hashlib.sha256(raw).hexdigest():
        raise AssertionError("transition payload SHA-256 mismatch")
    verify_ed25519(OLD_PUBLIC_KEY, envelope["signature"], TRANSITION_DOMAIN, raw, "trust transition")


def validate_final_state(raw: bytes, value: dict, genesis_raw: bytes, transition_raw: bytes, expected_source_sha: str) -> None:
    if raw != material_verify.canonical(value) or frozenset(value) != STATE_KEYS or value["schema"] != STATE_SCHEMA:
        raise AssertionError("invalid final trust-state encoding/schema")
    expected = {
        "schema": STATE_SCHEMA,
        "sequence": 1,
        "scope": MATERIAL_PAYLOAD_TYPE,
        "key_id": NEW_KEY_ID,
        "public_key": NEW_PUBLIC_KEY.hex(),
        "activation_source_commit": expected_source_sha,
        "predecessor_sha256": hashlib.sha256(genesis_raw).hexdigest(),
        "transition_sha256": hashlib.sha256(transition_raw).hexdigest(),
        "production": False,
    }
    if value != expected:
        raise AssertionError("final trust state does not match authorized transition chain")
    if value["sequence"] < MINIMUM_SEQUENCE:
        raise AssertionError(f"stale trust state below minimum sequence {MINIMUM_SEQUENCE}")
    if value["sequence"] != MINIMUM_SEQUENCE or value["key_id"] != NEW_KEY_ID or value["public_key"] != NEW_PUBLIC_KEY.hex():
        raise AssertionError("unexpected current trust root at rollback floor")


def verify_trust_and_successor(materials_path: Path, old_envelope_path: Path, genesis_path: Path, transition_path: Path, transition_envelope_path: Path, final_state_path: Path, new_envelope_path: Path, expected_source_sha: str) -> None:
    material_verify.rfc8032_selftest()
    materials_raw, materials = material_verify.load_canonical(materials_path, "materials")
    _, old_envelope = material_verify.load_canonical(old_envelope_path, "old material envelope")
    genesis_raw, genesis = material_verify.load_canonical(genesis_path, "genesis trust state")
    transition_raw, transition = material_verify.load_canonical(transition_path, "trust transition")
    _, transition_envelope = material_verify.load_canonical(transition_envelope_path, "trust transition envelope")
    final_raw, final_state = material_verify.load_canonical(final_state_path, "final trust state")
    _, new_envelope = material_verify.load_canonical(new_envelope_path, "new material envelope")

    payload_sha = validate_materials(materials_raw, materials, expected_source_sha)
    validate_material_envelope(old_envelope, OLD_KEY_ID, payload_sha)
    verify_ed25519(OLD_PUBLIC_KEY, old_envelope["signature"], MATERIAL_DOMAIN, materials_raw, "old material envelope")
    validate_genesis(genesis_raw, genesis)
    validate_transition(transition_raw, transition, transition_envelope, expected_source_sha)
    validate_final_state(final_raw, final_state, genesis_raw, transition_raw, expected_source_sha)
    validate_material_envelope(new_envelope, final_state["key_id"], payload_sha)
    verify_ed25519(bytes.fromhex(final_state["public_key"]), new_envelope["signature"], MATERIAL_DOMAIN, materials_raw, "successor material envelope")
    if old_envelope["payload_sha256"] != new_envelope["payload_sha256"]:
        raise AssertionError("old/new material envelopes disagree on payload")
    print(f"RUST-031 stdlib monotonic trust consumer: GREEN source={expected_source_sha} sequence={final_state['sequence']} key={final_state['key_id']}")


def verify(wheel_path: Path, rust_archive: Path, toolchain_path: Path, dep_root: Path, vendor_root: Path, cargo_lock: Path, build_lock: Path, source_sha: str, materials_path: Path, old_envelope_path: Path, genesis_path: Path, transition_path: Path, transition_envelope_path: Path, final_state_path: Path, new_envelope_path: Path) -> None:
    material_verify.verify(wheel_path, rust_archive, toolchain_path, dep_root, vendor_root, cargo_lock, build_lock, source_sha, materials_path, old_envelope_path)
    verify_trust_and_successor(materials_path, old_envelope_path, genesis_path, transition_path, transition_envelope_path, final_state_path, new_envelope_path, source_sha)


def expect_failure(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def selftest(materials_path: Path, old_envelope_path: Path, genesis_path: Path, transition_path: Path, transition_envelope_path: Path, final_state_path: Path, new_envelope_path: Path, expected_source_sha: str) -> None:
    verify_trust_and_successor(materials_path, old_envelope_path, genesis_path, transition_path, transition_envelope_path, final_state_path, new_envelope_path, expected_source_sha)
    _, genesis = material_verify.load_canonical(genesis_path, "genesis trust state")
    _, transition = material_verify.load_canonical(transition_path, "trust transition")
    _, transition_env = material_verify.load_canonical(transition_envelope_path, "trust transition envelope")
    _, final_state = material_verify.load_canonical(final_state_path, "final trust state")
    _, new_envelope = material_verify.load_canonical(new_envelope_path, "new material envelope")
    cases = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def write_obj(name: str, value: dict) -> Path:
            path = root / name
            path.write_bytes(material_verify.canonical(value))
            return path

        stale = write_obj("stale-state.json", genesis)
        expect_failure("stale-final-state", lambda: verify_trust_and_successor(materials_path, old_envelope_path, genesis_path, transition_path, transition_envelope_path, stale, new_envelope_path, expected_source_sha)); cases += 1

        value = copy.deepcopy(transition); value["sequence"] = 0
        bad = write_obj("rollback-transition.json", value)
        expect_failure("rollback-transition", lambda: verify_trust_and_successor(materials_path, old_envelope_path, genesis_path, bad, transition_envelope_path, final_state_path, new_envelope_path, expected_source_sha)); cases += 1

        value = copy.deepcopy(transition_env); sig = bytearray(material_verify.decode_signature(value["signature"])); sig[0] ^= 1; value["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        bad = write_obj("bad-transition-signature.json", value)
        expect_failure("transition-signature", lambda: verify_trust_and_successor(materials_path, old_envelope_path, genesis_path, transition_path, bad, final_state_path, new_envelope_path, expected_source_sha)); cases += 1

        value = copy.deepcopy(final_state); value["predecessor_sha256"] = "0" * 64
        bad = write_obj("bad-predecessor.json", value)
        expect_failure("predecessor-digest", lambda: verify_trust_and_successor(materials_path, old_envelope_path, genesis_path, transition_path, transition_envelope_path, bad, new_envelope_path, expected_source_sha)); cases += 1

        value = copy.deepcopy(final_state); value["transition_sha256"] = "0" * 64
        bad = write_obj("bad-transition-digest.json", value)
        expect_failure("transition-digest", lambda: verify_trust_and_successor(materials_path, old_envelope_path, genesis_path, transition_path, transition_envelope_path, bad, new_envelope_path, expected_source_sha)); cases += 1

        value = copy.deepcopy(final_state); value["key_id"] = OLD_KEY_ID; value["public_key"] = OLD_PUBLIC_KEY.hex()
        bad = write_obj("downgrade-key.json", value)
        expect_failure("current-key-downgrade", lambda: verify_trust_and_successor(materials_path, old_envelope_path, genesis_path, transition_path, transition_envelope_path, bad, new_envelope_path, expected_source_sha)); cases += 1

        value = copy.deepcopy(new_envelope); value["key_id"] = OLD_KEY_ID
        bad = write_obj("wrong-new-key-id.json", value)
        expect_failure("successor-key-id", lambda: verify_trust_and_successor(materials_path, old_envelope_path, genesis_path, transition_path, transition_envelope_path, final_state_path, bad, expected_source_sha)); cases += 1

        value = copy.deepcopy(new_envelope); sig = bytearray(material_verify.decode_signature(value["signature"])); sig[-1] ^= 1; value["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        bad = write_obj("bad-successor-signature.json", value)
        expect_failure("successor-signature", lambda: verify_trust_and_successor(materials_path, old_envelope_path, genesis_path, transition_path, transition_envelope_path, final_state_path, bad, expected_source_sha)); cases += 1

        value = copy.deepcopy(new_envelope); value["payload_sha256"] = "0" * 64
        bad = write_obj("bad-successor-payload.json", value)
        expect_failure("successor-payload", lambda: verify_trust_and_successor(materials_path, old_envelope_path, genesis_path, transition_path, transition_envelope_path, final_state_path, bad, expected_source_sha)); cases += 1

        expect_failure("activation-source", lambda: verify_trust_and_successor(materials_path, old_envelope_path, genesis_path, transition_path, transition_envelope_path, final_state_path, new_envelope_path, "0" * 40)); cases += 1

        noncanonical = root / "noncanonical-state.json"
        noncanonical.write_text(json.dumps(final_state, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-final-state", lambda: verify_trust_and_successor(materials_path, old_envelope_path, genesis_path, transition_path, transition_envelope_path, noncanonical, new_envelope_path, expected_source_sha)); cases += 1

    if cases != 11:
        raise AssertionError(f"unexpected RUST-031 selftest case count: {cases}")
    print("RUST-031 stdlib monotonic trust fail-closed contract: 11/11 expected cases passed")


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: rust_031_stdlib_trust_state_material_verify.py verify|selftest ...")
    cmd = sys.argv[1]
    if cmd == "verify" and len(sys.argv) == 17:
        verify(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), Path(sys.argv[6]), Path(sys.argv[7]), Path(sys.argv[8]), sys.argv[9], Path(sys.argv[10]), Path(sys.argv[11]), Path(sys.argv[12]), Path(sys.argv[13]), Path(sys.argv[14]), Path(sys.argv[15]), Path(sys.argv[16]))
    elif cmd == "selftest" and len(sys.argv) == 10:
        selftest(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), Path(sys.argv[6]), Path(sys.argv[7]), Path(sys.argv[8]), sys.argv[9])
    else:
        raise SystemExit("invalid RUST-031 command/arguments")


if __name__ == "__main__":
    main()
