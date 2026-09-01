#!/usr/bin/env python3
"""RUST-010: seal and verify an offline test-only native provenance attestation envelope."""
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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PROVENANCE_SCHEMA = "axven-native-artifact-provenance-v1"
ATTESTATION_SCHEMA = "axven-native-attestation-envelope-v1"
PAYLOAD_TYPE = "application/vnd.axven.native-provenance.v1+json"
ALGORITHM = "ed25519"
KEY_ID = "rust-010-test-only-ed25519-v1"
DOMAIN = b"AXVEN_NATIVE_ATTESTATION_V1\x00"
TEST_SEED = bytes.fromhex("6d6804baeaa0ff8428d6d6a1b51b015b079bb0fe99d3ff6fbcb5785f0210d34a")
PINNED_PUBLIC_KEY = bytes.fromhex("7569ab4f72cba7d82e48b43d91ad964a73d5d498a1df6e75271fc92bf57cb54e")
HEX = frozenset("0123456789abcdef")
ENVELOPE_KEYS = frozenset(
    {"schema", "algorithm", "key_id", "payload_type", "payload_sha256", "signature"}
)


def _canonical(obj: object) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _lower_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(ch in HEX for ch in value)


def _load_canonical_json(path: Path, *, label: str) -> tuple[bytes, dict]:
    raw = path.read_bytes()
    loaded = json.loads(raw.decode("utf-8"))
    if not isinstance(loaded, dict):
        raise AssertionError(f"{label} must be a JSON object")
    if raw != _canonical(loaded):
        raise AssertionError(f"{label} is not canonical JSON")
    return raw, loaded


def _load_provenance(path: Path) -> tuple[bytes, dict]:
    raw, loaded = _load_canonical_json(path, label="provenance")
    if loaded.get("schema") != PROVENANCE_SCHEMA:
        raise AssertionError("unexpected provenance schema")
    if loaded.get("production_consensus") != "python":
        raise AssertionError("provenance does not preserve Python consensus authority")
    source = loaded.get("source")
    artifact = loaded.get("artifact")
    if not isinstance(source, dict) or source.get("repository") != "AxvenLabs/axven-core":
        raise AssertionError("unexpected provenance repository")
    if not _lower_hex(source.get("commit"), 40):
        raise AssertionError("invalid provenance source commit")
    if not isinstance(artifact, dict) or not _lower_hex(artifact.get("sha256"), 64):
        raise AssertionError("invalid provenance artifact digest")
    return raw, loaded


def _message(payload: bytes) -> bytes:
    return DOMAIN + len(payload).to_bytes(8, "big") + payload


def _private_key() -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    derived = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if derived != PINNED_PUBLIC_KEY:
        raise AssertionError("RUST-010 pinned test key mismatch")
    return key


def _decode_signature(value: object) -> bytes:
    if not isinstance(value, str):
        raise AssertionError("signature must be base64 text")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise AssertionError("invalid base64 signature") from exc
    if len(raw) != 64:
        raise AssertionError("invalid Ed25519 signature length")
    if base64.b64encode(raw).decode("ascii") != value:
        raise AssertionError("non-canonical base64 signature")
    return raw


def _make_envelope(payload: bytes) -> dict:
    signature = _private_key().sign(_message(payload))
    return {
        "schema": ATTESTATION_SCHEMA,
        "algorithm": ALGORITHM,
        "key_id": KEY_ID,
        "payload_type": PAYLOAD_TYPE,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def seal(provenance_path: Path, envelope_path: Path) -> None:
    payload, _ = _load_provenance(provenance_path)
    envelope_path.write_bytes(_canonical(_make_envelope(payload)))
    print(
        "RUST-010 test-only envelope sealed "
        f"payload_sha256={hashlib.sha256(payload).hexdigest()} file={envelope_path.name}"
    )


def verify(provenance_path: Path, envelope_path: Path) -> None:
    payload, _ = _load_provenance(provenance_path)
    _, envelope = _load_canonical_json(envelope_path, label="attestation envelope")
    if frozenset(envelope) != ENVELOPE_KEYS:
        raise AssertionError("unexpected attestation envelope fields")
    expected_policy = {
        "schema": ATTESTATION_SCHEMA,
        "algorithm": ALGORITHM,
        "key_id": KEY_ID,
        "payload_type": PAYLOAD_TYPE,
    }
    for name, expected in expected_policy.items():
        if envelope.get(name) != expected:
            raise AssertionError(f"attestation policy mismatch: {name}")
    digest = hashlib.sha256(payload).hexdigest()
    if envelope.get("payload_sha256") != digest:
        raise AssertionError("attestation payload digest mismatch")
    signature = _decode_signature(envelope.get("signature"))
    public_key = Ed25519PublicKey.from_public_bytes(PINNED_PUBLIC_KEY)
    try:
        public_key.verify(signature, _message(payload))
    except InvalidSignature as exc:
        raise AssertionError("attestation signature verification failed") from exc
    print(f"RUST-010 offline attestation envelope: GREEN payload_sha256={digest}")


def _must_reject(provenance: Path, envelope: Path, label: str) -> None:
    try:
        verify(provenance, envelope)
    except (AssertionError, json.JSONDecodeError, UnicodeDecodeError):
        print(f"[GREEN] rejected {label}")
        return
    raise AssertionError(f"tamper case unexpectedly accepted: {label}")


def selftest(provenance_path: Path, envelope_path: Path) -> None:
    verify(provenance_path, envelope_path)
    payload_raw, payload = _load_provenance(provenance_path)
    envelope_raw, envelope = _load_canonical_json(envelope_path, label="attestation envelope")

    with tempfile.TemporaryDirectory(prefix="axven-rust010-") as temp:
        root = Path(temp)

        tampered_payload = copy.deepcopy(payload)
        digest = tampered_payload["artifact"]["sha256"]
        tampered_payload["artifact"]["sha256"] = ("0" if digest[0] != "0" else "1") + digest[1:]
        p = root / "tampered-provenance.json"
        p.write_bytes(_canonical(tampered_payload))
        _must_reject(p, envelope_path, "payload tamper")

        tampered_signature = copy.deepcopy(envelope)
        sig = bytearray(_decode_signature(tampered_signature["signature"]))
        sig[0] ^= 0x01
        tampered_signature["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        e = root / "tampered-signature.json"
        e.write_bytes(_canonical(tampered_signature))
        _must_reject(provenance_path, e, "signature tamper")

        wrong_key = copy.deepcopy(envelope)
        wrong_key["key_id"] = "untrusted-key"
        e = root / "wrong-key.json"
        e.write_bytes(_canonical(wrong_key))
        _must_reject(provenance_path, e, "key-id substitution")

        wrong_algorithm = copy.deepcopy(envelope)
        wrong_algorithm["algorithm"] = "none"
        e = root / "wrong-algorithm.json"
        e.write_bytes(_canonical(wrong_algorithm))
        _must_reject(provenance_path, e, "algorithm substitution")

        extra_field = copy.deepcopy(envelope)
        extra_field["public_key"] = PINNED_PUBLIC_KEY.hex()
        e = root / "extra-field.json"
        e.write_bytes(_canonical(extra_field))
        _must_reject(provenance_path, e, "embedded trust-root substitution")

        noncanonical = root / "noncanonical-envelope.json"
        noncanonical.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
        _must_reject(provenance_path, noncanonical, "non-canonical envelope")

    if payload_raw != provenance_path.read_bytes() or envelope_raw != envelope_path.read_bytes():
        raise AssertionError("selftest mutated source evidence")
    print("RUST-010 fail-closed mutation contract: 6/6 GREEN")


def main() -> None:
    if len(sys.argv) != 4 or sys.argv[1] not in {"seal", "verify", "selftest"}:
        raise SystemExit(
            "usage: rust_010_native_attestation.py {seal|verify|selftest} "
            "PROVENANCE ENVELOPE"
        )
    provenance = Path(sys.argv[2])
    envelope = Path(sys.argv[3])
    if sys.argv[1] == "seal":
        seal(provenance, envelope)
    elif sys.argv[1] == "verify":
        verify(provenance, envelope)
    else:
        selftest(provenance, envelope)


if __name__ == "__main__":
    main()
