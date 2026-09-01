#!/usr/bin/env python3
"""RUST-028: verification-only TEST-ONLY trust-root rotation continuity verifier."""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MATERIAL_SCHEMA = "axven-native-build-materials-v1"
MATERIAL_ENVELOPE_SCHEMA = "axven-native-build-material-attestation-envelope-v1"
MATERIAL_PAYLOAD_TYPE = "application/vnd.axven.native-build-materials.v1+json"
MATERIAL_DOMAIN = b"AXVEN_NATIVE_BUILD_MATERIAL_ATTESTATION_V1\x00"
TRANSITION_SCHEMA = "axven-native-trust-transition-v1"
TRANSITION_ENVELOPE_SCHEMA = "axven-native-trust-transition-envelope-v1"
TRANSITION_PAYLOAD_TYPE = "application/vnd.axven.native-trust-transition.v1+json"
TRANSITION_DOMAIN = b"AXVEN_NATIVE_TRUST_TRANSITION_V1\x00"
ALGORITHM = "ed25519"
OLD_KEY_ID = "rust-026-test-only-ed25519-v1"
OLD_PUBLIC_KEY = bytes.fromhex("4dd000548d1ed66588e6c23531163bd12c9c5dbca5eb932d4c6a75cde6525064")
NEW_KEY_ID = "rust-028-test-only-ed25519-v2"
NEW_PUBLIC_KEY = bytes.fromhex("158d55a155c9191d0783d48c1a1a1531fe65a783356c5b221e6952e57d58fdb3")
REPOSITORY = "AxvenLabs/axven-core"
HEX = frozenset("0123456789abcdef")
ENVELOPE_KEYS = frozenset({"schema", "algorithm", "key_id", "payload_type", "payload_sha256", "signature"})
TRANSITION_KEYS = frozenset({"schema", "sequence", "scope", "from_key_id", "from_public_key", "to_key_id", "to_public_key", "activation_source_commit", "production"})


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def lower_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(ch in HEX for ch in value)


def assert_regular(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise AssertionError(f"{label} must be a real regular file")


def load_canonical(path: Path, label: str) -> tuple[bytes, dict]:
    assert_regular(path, label)
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or raw != canonical(value):
        raise AssertionError(f"{label} must be canonical JSON object")
    return raw, value


def decode_signature(value: object) -> bytes:
    if not isinstance(value, str):
        raise AssertionError("signature must be base64 text")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise AssertionError("invalid base64 signature") from exc
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != value:
        raise AssertionError("invalid/non-canonical Ed25519 signature")
    return raw


def signed_message(domain: bytes, payload: bytes) -> bytes:
    return domain + len(payload).to_bytes(8, "big") + payload


def verify_signature(public_key: bytes, signature: object, domain: bytes, payload: bytes, label: str) -> None:
    sig = decode_signature(signature)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(sig, signed_message(domain, payload))
    except InvalidSignature as exc:
        raise AssertionError(f"{label} signature mismatch") from exc


def validate_materials(raw: bytes, value: dict, expected_source_sha: str) -> str:
    if value.get("schema") != MATERIAL_SCHEMA:
        raise AssertionError("unexpected materials schema")
    source = value.get("source")
    if not isinstance(source, dict) or set(source) != {"repository", "commit"}:
        raise AssertionError("unexpected materials source identity")
    if source["repository"] != REPOSITORY:
        raise AssertionError("unexpected materials repository")
    if source["commit"] != expected_source_sha or not lower_hex(expected_source_sha, 40):
        raise AssertionError("materials source commit mismatch")
    return hashlib.sha256(raw).hexdigest()


def validate_material_envelope(envelope: dict, *, expected_key_id: str, expected_payload_sha256: str) -> None:
    if frozenset(envelope) != ENVELOPE_KEYS:
        raise AssertionError("unexpected material envelope fields")
    if envelope["schema"] != MATERIAL_ENVELOPE_SCHEMA or envelope["algorithm"] != ALGORITHM or envelope["key_id"] != expected_key_id or envelope["payload_type"] != MATERIAL_PAYLOAD_TYPE:
        raise AssertionError("unexpected material envelope policy")
    if envelope["payload_sha256"] != expected_payload_sha256:
        raise AssertionError("material payload SHA-256 mismatch")


def validate_transition(value: dict, expected_source_sha: str) -> None:
    if frozenset(value) != TRANSITION_KEYS or value["schema"] != TRANSITION_SCHEMA:
        raise AssertionError("unexpected transition fields/schema")
    if value["sequence"] != 1:
        raise AssertionError("transition rollback/sequence mismatch")
    if value["scope"] != MATERIAL_PAYLOAD_TYPE:
        raise AssertionError("transition scope mismatch")
    if value["from_key_id"] != OLD_KEY_ID or value["from_public_key"] != OLD_PUBLIC_KEY.hex():
        raise AssertionError("transition old trust root mismatch")
    if value["to_key_id"] != NEW_KEY_ID or value["to_public_key"] != NEW_PUBLIC_KEY.hex():
        raise AssertionError("transition new trust root mismatch")
    if OLD_PUBLIC_KEY == NEW_PUBLIC_KEY:
        raise AssertionError("old/new trust roots must be distinct")
    if value["activation_source_commit"] != expected_source_sha or not lower_hex(expected_source_sha, 40):
        raise AssertionError("transition activation source mismatch")
    if value["production"] is not False:
        raise AssertionError("RUST-028 transition must remain TEST-ONLY/non-production")


def validate_transition_envelope(envelope: dict, payload_sha256: str) -> None:
    if frozenset(envelope) != ENVELOPE_KEYS:
        raise AssertionError("unexpected transition envelope fields")
    if envelope["schema"] != TRANSITION_ENVELOPE_SCHEMA or envelope["algorithm"] != ALGORITHM or envelope["key_id"] != OLD_KEY_ID or envelope["payload_type"] != TRANSITION_PAYLOAD_TYPE or envelope["payload_sha256"] != payload_sha256:
        raise AssertionError("unexpected transition envelope policy")


def verify(materials_path: Path, old_envelope_path: Path, transition_path: Path, transition_envelope_path: Path, new_envelope_path: Path, expected_source_sha: str) -> None:
    materials_raw, materials = load_canonical(materials_path, "materials")
    _, old_envelope = load_canonical(old_envelope_path, "old material envelope")
    transition_raw, transition = load_canonical(transition_path, "trust transition")
    _, transition_envelope = load_canonical(transition_envelope_path, "trust transition envelope")
    _, new_envelope = load_canonical(new_envelope_path, "new material envelope")
    payload_sha = validate_materials(materials_raw, materials, expected_source_sha)
    validate_material_envelope(old_envelope, expected_key_id=OLD_KEY_ID, expected_payload_sha256=payload_sha)
    verify_signature(OLD_PUBLIC_KEY, old_envelope["signature"], MATERIAL_DOMAIN, materials_raw, "old material envelope")
    validate_transition(transition, expected_source_sha)
    transition_sha = hashlib.sha256(transition_raw).hexdigest()
    validate_transition_envelope(transition_envelope, transition_sha)
    verify_signature(OLD_PUBLIC_KEY, transition_envelope["signature"], TRANSITION_DOMAIN, transition_raw, "trust transition")
    validate_material_envelope(new_envelope, expected_key_id=NEW_KEY_ID, expected_payload_sha256=payload_sha)
    verify_signature(NEW_PUBLIC_KEY, new_envelope["signature"], MATERIAL_DOMAIN, materials_raw, "new material envelope")
    if old_envelope["payload_sha256"] != new_envelope["payload_sha256"]:
        raise AssertionError("old/new material envelopes disagree on payload")
    print(f"RUST-028 trust-root rotation continuity: GREEN source={expected_source_sha} old={OLD_KEY_ID} new={NEW_KEY_ID}")


def expect_failure(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def selftest(materials_path: Path, old_envelope_path: Path, transition_path: Path, transition_envelope_path: Path, new_envelope_path: Path, expected_source_sha: str) -> None:
    verify(materials_path, old_envelope_path, transition_path, transition_envelope_path, new_envelope_path, expected_source_sha)
    _, transition_base = load_canonical(transition_path, "trust transition")
    _, transition_env_base = load_canonical(transition_envelope_path, "trust transition envelope")
    _, old_env_base = load_canonical(old_envelope_path, "old material envelope")
    _, new_env_base = load_canonical(new_envelope_path, "new material envelope")
    _, materials_base = load_canonical(materials_path, "materials")
    cases = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        def write_obj(name: str, value: dict) -> Path:
            path = root / name
            path.write_bytes(canonical(value))
            return path

        value = copy.deepcopy(transition_base); value["sequence"] = 0
        bad = write_obj("rollback.json", value)
        expect_failure("rollback-sequence", lambda: verify(materials_path, old_envelope_path, bad, transition_envelope_path, new_envelope_path, expected_source_sha)); cases += 1

        value = copy.deepcopy(transition_base); value["from_key_id"] = "unknown-old-key"
        bad = write_obj("unknown-old.json", value)
        expect_failure("unknown-old-key", lambda: verify(materials_path, old_envelope_path, bad, transition_envelope_path, new_envelope_path, expected_source_sha)); cases += 1

        value = copy.deepcopy(transition_base); value["to_public_key"] = "00" * 32
        bad = write_obj("new-key-substitution.json", value)
        expect_failure("new-key-substitution", lambda: verify(materials_path, old_envelope_path, bad, transition_envelope_path, new_envelope_path, expected_source_sha)); cases += 1

        value = copy.deepcopy(transition_env_base); sig = bytearray(decode_signature(value["signature"])); sig[0] ^= 1; value["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        bad = write_obj("bad-transition-signature.json", value)
        expect_failure("transition-signature", lambda: verify(materials_path, old_envelope_path, transition_path, bad, new_envelope_path, expected_source_sha)); cases += 1

        value = copy.deepcopy(new_env_base); sig = bytearray(decode_signature(value["signature"])); sig[-1] ^= 1; value["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        bad = write_obj("bad-new-signature.json", value)
        expect_failure("new-signature", lambda: verify(materials_path, old_envelope_path, transition_path, transition_envelope_path, bad, expected_source_sha)); cases += 1

        value = copy.deepcopy(old_env_base); sig = bytearray(decode_signature(value["signature"])); sig[1] ^= 1; value["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        bad = write_obj("bad-old-signature.json", value)
        expect_failure("old-signature", lambda: verify(materials_path, bad, transition_path, transition_envelope_path, new_envelope_path, expected_source_sha)); cases += 1

        value = copy.deepcopy(new_env_base); value["payload_sha256"] = "00" * 32
        bad = write_obj("payload-disagreement.json", value)
        expect_failure("payload-disagreement", lambda: verify(materials_path, old_envelope_path, transition_path, transition_envelope_path, bad, expected_source_sha)); cases += 1

        noncanonical = root / "noncanonical-transition.json"
        noncanonical.write_text(json.dumps(transition_base, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-transition", lambda: verify(materials_path, old_envelope_path, noncanonical, transition_envelope_path, new_envelope_path, expected_source_sha)); cases += 1

        expect_failure("activation-source", lambda: verify(materials_path, old_envelope_path, transition_path, transition_envelope_path, new_envelope_path, "0" * 40)); cases += 1

        value = copy.deepcopy(materials_base); value["source"]["commit"] = "f" * 40
        bad_materials = write_obj("bad-material-source.json", value)
        expect_failure("material-source", lambda: verify(bad_materials, old_envelope_path, transition_path, transition_envelope_path, new_envelope_path, expected_source_sha)); cases += 1

    if cases != 10:
        raise AssertionError(f"unexpected RUST-028 selftest case count: {cases}")
    print("RUST-028 trust-root rotation fail-closed contract: 10/10 expected cases passed")


def main() -> None:
    if len(sys.argv) != 8 or sys.argv[1] not in {"verify", "selftest"}:
        raise SystemExit("usage: rust_028_trust_root_rotation_verify.py verify|selftest materials old-envelope transition transition-envelope new-envelope source-sha")
    fn = verify if sys.argv[1] == "verify" else selftest
    fn(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), Path(sys.argv[6]), sys.argv[7])


if __name__ == "__main__":
    main()
