#!/usr/bin/env python3
"""RUST-011: portable native provenance + TEST-ONLY attestation candidate."""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parent
WHEELHOUSE = ROOT / "wheelhouse-portable"
PROVENANCE_SCHEMA = "axven-native-portable-provenance-v1"
ATTESTATION_SCHEMA = "axven-native-portable-attestation-envelope-v1"
PAYLOAD_TYPE = "application/vnd.axven.native-portable-provenance.v1+json"
ALGORITHM = "ed25519"
KEY_ID = "rust-011-test-only-ed25519-v1"
DOMAIN = b"AXVEN_NATIVE_PORTABLE_ATTESTATION_V1\x00"
MANYLINUX_IMAGE = (
    "quay.io/pypa/manylinux_2_28_x86_64@"
    "sha256:443eabd378e140996780a772e12c1a1ef10551da933fe76d74a1bab61f68a7b7"
)
TEST_SEED = bytes.fromhex("60fe5e0dc44f198896c25ef95c4dd8860dce39c86f556475b6d1273463f3acba")
PINNED_PUBLIC_KEY = bytes.fromhex("36868181c4f61de13030919ed7d03d6f517a7a1a9e15fde821579e09852c6722")
HEX = frozenset("0123456789abcdef")
BUILD_INPUTS = (
    "native/axven_native/Cargo.toml",
    "native/axven_native/Cargo.lock",
    "native/axven_native/src/lib.rs",
    "requirements-native-build.lock",
    "requirements-ci-runtime-posix.lock",
    "rust_009_portable_linux_wheel_spec.py",
    ".github/workflows/native-portable-attestation.yml",
)
ENVELOPE_KEYS = frozenset(
    {"schema", "algorithm", "key_id", "payload_type", "payload_sha256", "signature"}
)


def _canonical(obj: object) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _lower_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(ch in HEX for ch in value)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_canonical_json(path: Path, *, label: str) -> tuple[bytes, dict]:
    raw = path.read_bytes()
    loaded = json.loads(raw.decode("utf-8"))
    if not isinstance(loaded, dict):
        raise AssertionError(f"{label} must be a JSON object")
    if raw != _canonical(loaded):
        raise AssertionError(f"{label} is not canonical JSON")
    return raw, loaded


def _source_identity() -> dict:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    source_sha = os.environ.get("AXVEN_SOURCE_SHA", "").lower()
    github_sha = os.environ.get("GITHUB_SHA", "").lower()
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if repository != "AxvenLabs/axven-core":
        raise AssertionError(repository)
    if not _lower_hex(source_sha, 40) or not _lower_hex(github_sha, 40):
        raise AssertionError((source_sha, github_sha))
    if not run_id.isdigit() or not run_attempt.isdigit():
        raise AssertionError((run_id, run_attempt))
    checkout_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, encoding="utf-8"
    ).strip().lower()
    if checkout_sha != source_sha:
        raise AssertionError((checkout_sha, source_sha))
    return {
        "repository": repository,
        "commit": source_sha,
        "github_context_sha": github_sha,
        "run_id": int(run_id),
        "run_attempt": int(run_attempt),
    }


def _single_wheel() -> Path:
    wheels = sorted(WHEELHOUSE.glob("*.whl"))
    if len(wheels) != 1:
        raise AssertionError(f"expected exactly one portable wheel, got {wheels!r}")
    wheel = wheels[0]
    if not wheel.name.startswith("axven_native-0.1.0-"):
        raise AssertionError(wheel.name)
    if not wheel.name.endswith("-cp313-abi3-manylinux_2_28_x86_64.whl"):
        raise AssertionError(f"unexpected portable wheel tag: {wheel.name}")
    if wheel.stat().st_size <= 0:
        raise AssertionError("empty portable wheel")
    return wheel


def _build_inputs() -> dict:
    result: dict[str, str] = {}
    for relative in BUILD_INPUTS:
        path = ROOT / relative
        digest = _sha256_file(path)
        if not _lower_hex(digest, 64):
            raise AssertionError((relative, digest))
        result[relative] = digest
    return result


def _expected_provenance() -> dict:
    image = os.environ.get("MANYLINUX_IMAGE", "")
    if image != MANYLINUX_IMAGE:
        raise AssertionError(f"unexpected manylinux image: {image!r}")
    wheel = _single_wheel()
    return {
        "schema": PROVENANCE_SCHEMA,
        "source": _source_identity(),
        "builder": {
            "image": MANYLINUX_IMAGE,
            "compatibility": "manylinux_2_28",
            "architecture": "x86_64",
            "python": "3.13.15",
            "rust": "1.98.0",
            "maturin": "1.15.0",
            "pyo3": "0.29.2",
        },
        "artifact": {
            "filename": wheel.name,
            "sha256": _sha256_file(wheel),
            "bytes": wheel.stat().st_size,
        },
        "build_inputs": _build_inputs(),
        "production_consensus": "python",
    }


def generate(provenance_path: Path) -> None:
    provenance = _expected_provenance()
    provenance_path.write_bytes(_canonical(provenance))
    print(
        "RUST-011 portable provenance generated "
        f"artifact_sha256={provenance['artifact']['sha256']} "
        f"source={provenance['source']['commit']}"
    )


def _load_provenance(provenance_path: Path) -> tuple[bytes, dict]:
    raw, loaded = _load_canonical_json(provenance_path, label="portable provenance")
    if loaded != _expected_provenance():
        raise AssertionError("portable provenance does not match current source/build/artifact identity")
    return raw, loaded


def _private_key() -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    derived = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if derived != PINNED_PUBLIC_KEY:
        raise AssertionError("RUST-011 pinned test key mismatch")
    return key


def _header(payload: bytes) -> dict:
    return {
        "schema": ATTESTATION_SCHEMA,
        "algorithm": ALGORITHM,
        "key_id": KEY_ID,
        "payload_type": PAYLOAD_TYPE,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }


def _message(payload: bytes, header: dict) -> bytes:
    header_bytes = _canonical(header)
    return (
        DOMAIN
        + len(header_bytes).to_bytes(8, "big")
        + header_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    )


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


def seal(provenance_path: Path, envelope_path: Path) -> None:
    payload, _ = _load_provenance(provenance_path)
    header = _header(payload)
    signature = _private_key().sign(_message(payload, header))
    envelope = dict(header)
    envelope["signature"] = base64.b64encode(signature).decode("ascii")
    envelope_path.write_bytes(_canonical(envelope))
    print(f"RUST-011 TEST-ONLY portable attestation sealed payload_sha256={header['payload_sha256']}")


def verify(provenance_path: Path, envelope_path: Path) -> None:
    payload, _ = _load_provenance(provenance_path)
    _, envelope = _load_canonical_json(envelope_path, label="portable attestation envelope")
    if frozenset(envelope) != ENVELOPE_KEYS:
        raise AssertionError("unexpected portable attestation envelope fields")
    header = {name: envelope[name] for name in envelope if name != "signature"}
    if header != _header(payload):
        raise AssertionError("portable attestation policy or payload digest mismatch")
    signature = _decode_signature(envelope.get("signature"))
    public_key = Ed25519PublicKey.from_public_bytes(PINNED_PUBLIC_KEY)
    try:
        public_key.verify(signature, _message(payload, header))
    except InvalidSignature as exc:
        raise AssertionError("portable attestation signature verification failed") from exc
    print(f"RUST-011 portable attested candidate: GREEN payload_sha256={header['payload_sha256']}")


def _must_reject(provenance: Path, envelope: Path, label: str) -> None:
    try:
        verify(provenance, envelope)
    except (AssertionError, json.JSONDecodeError, UnicodeDecodeError):
        print(f"[GREEN] rejected {label}")
        return
    raise AssertionError(f"tamper case unexpectedly accepted: {label}")


def selftest(provenance_path: Path, envelope_path: Path) -> None:
    verify(provenance_path, envelope_path)
    payload_raw, payload = _load_canonical_json(provenance_path, label="portable provenance")
    envelope_raw, envelope = _load_canonical_json(envelope_path, label="portable attestation envelope")

    with tempfile.TemporaryDirectory(prefix="axven-rust011-") as temp:
        root = Path(temp)

        tampered_payload = copy.deepcopy(payload)
        digest = tampered_payload["artifact"]["sha256"]
        tampered_payload["artifact"]["sha256"] = ("0" if digest[0] != "0" else "1") + digest[1:]
        p = root / "tampered-provenance.json"
        p.write_bytes(_canonical(tampered_payload))
        _must_reject(p, envelope_path, "artifact digest tamper")

        tampered_builder = copy.deepcopy(payload)
        tampered_builder["builder"]["image"] = "quay.io/pypa/manylinux_2_28_x86_64@sha256:" + "0" * 64
        p = root / "tampered-builder.json"
        p.write_bytes(_canonical(tampered_builder))
        _must_reject(p, envelope_path, "builder image substitution")

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
    print("RUST-011 fail-closed mutation contract: 7/7 GREEN")


def main() -> None:
    if len(sys.argv) < 3:
        raise SystemExit(
            "usage: rust_011_portable_attestation.py generate PROVENANCE | "
            "{seal|verify|selftest} PROVENANCE ENVELOPE"
        )
    command = sys.argv[1]
    if command == "generate" and len(sys.argv) == 3:
        generate(Path(sys.argv[2]))
        return
    if command in {"seal", "verify", "selftest"} and len(sys.argv) == 4:
        provenance = Path(sys.argv[2])
        envelope = Path(sys.argv[3])
        if command == "seal":
            seal(provenance, envelope)
        elif command == "verify":
            verify(provenance, envelope)
        else:
            selftest(provenance, envelope)
        return
    raise SystemExit(
        "usage: rust_011_portable_attestation.py generate PROVENANCE | "
        "{seal|verify|selftest} PROVENANCE ENVELOPE"
    )


if __name__ == "__main__":
    main()
