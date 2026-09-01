#!/usr/bin/env python3
"""RUST-012: detached offline verifier for the portable native evidence triple."""
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

PROVENANCE_SCHEMA = "axven-native-portable-provenance-v1"
ATTESTATION_SCHEMA = "axven-native-portable-attestation-envelope-v1"
PAYLOAD_TYPE = "application/vnd.axven.native-portable-provenance.v1+json"
ALGORITHM = "ed25519"
KEY_ID = "rust-011-test-only-ed25519-v1"
DOMAIN = b"AXVEN_NATIVE_PORTABLE_ATTESTATION_V1\x00"
PINNED_PUBLIC_KEY = bytes.fromhex("36868181c4f61de13030919ed7d03d6f517a7a1a9e15fde821579e09852c6722")
REPOSITORY = "AxvenLabs/axven-core"
WHEEL_FILENAME = "axven_native-0.1.0-cp313-abi3-manylinux_2_28_x86_64.whl"
MANYLINUX_IMAGE = (
    "quay.io/pypa/manylinux_2_28_x86_64@"
    "sha256:443eabd378e140996780a772e12c1a1ef10551da933fe76d74a1bab61f68a7b7"
)
BUILDER_POLICY = {
    "image": MANYLINUX_IMAGE,
    "compatibility": "manylinux_2_28",
    "architecture": "x86_64",
    "python": "3.13.13",
    "rust": "1.98.0",
    "maturin": "1.15.0",
    "pyo3": "0.29.2",
}
BUILD_INPUT_KEYS = frozenset(
    {
        "native/axven_native/Cargo.toml",
        "native/axven_native/Cargo.lock",
        "native/axven_native/src/lib.rs",
        "requirements-native-build.lock",
        "requirements-ci-runtime-posix.lock",
        "rust_009_portable_linux_wheel_spec.py",
        ".github/workflows/native-portable-attestation.yml",
    }
)
PROVENANCE_KEYS = frozenset(
    {"schema", "source", "builder", "artifact", "build_inputs", "production_consensus"}
)
SOURCE_KEYS = frozenset({"repository", "commit", "github_context_sha", "run_id", "run_attempt"})
ARTIFACT_KEYS = frozenset({"filename", "sha256", "bytes"})
ENVELOPE_KEYS = frozenset(
    {"schema", "algorithm", "key_id", "payload_type", "payload_sha256", "signature"}
)
HEX = frozenset("0123456789abcdef")


def _canonical(obj: object) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _lower_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(ch in HEX for ch in value)


def _assert_regular_file(path: Path, label: str) -> None:
    if path.is_symlink():
        raise AssertionError(f"{label} must not be a symlink")
    if not path.is_file():
        raise AssertionError(f"{label} must be a regular file")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_canonical_json(path: Path, *, label: str) -> tuple[bytes, dict]:
    _assert_regular_file(path, label)
    raw = path.read_bytes()
    loaded = json.loads(raw.decode("utf-8"))
    if not isinstance(loaded, dict):
        raise AssertionError(f"{label} must be a JSON object")
    if raw != _canonical(loaded):
        raise AssertionError(f"{label} is not canonical JSON")
    return raw, loaded


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


def _validate_source(source: object) -> dict:
    if not isinstance(source, dict) or frozenset(source) != SOURCE_KEYS:
        raise AssertionError("unexpected source identity fields")
    if source["repository"] != REPOSITORY:
        raise AssertionError("unexpected source repository")
    if not _lower_hex(source["commit"], 40):
        raise AssertionError("invalid source commit")
    if not _lower_hex(source["github_context_sha"], 40):
        raise AssertionError("invalid GitHub context SHA claim")
    if type(source["run_id"]) is not int or source["run_id"] <= 0:
        raise AssertionError("invalid run_id claim")
    if type(source["run_attempt"]) is not int or source["run_attempt"] <= 0:
        raise AssertionError("invalid run_attempt claim")
    return source


def _validate_artifact(artifact: object, wheel: Path) -> dict:
    if not isinstance(artifact, dict) or frozenset(artifact) != ARTIFACT_KEYS:
        raise AssertionError("unexpected artifact fields")
    if artifact["filename"] != WHEEL_FILENAME or wheel.name != WHEEL_FILENAME:
        raise AssertionError("portable wheel filename/path binding mismatch")
    if not _lower_hex(artifact["sha256"], 64):
        raise AssertionError("invalid artifact SHA-256 claim")
    actual_sha256 = _sha256_file(wheel)
    if artifact["sha256"] != actual_sha256:
        raise AssertionError("portable wheel SHA-256 mismatch")
    if type(artifact["bytes"]) is not int or artifact["bytes"] <= 0:
        raise AssertionError("invalid artifact byte-length claim")
    if artifact["bytes"] != wheel.stat().st_size:
        raise AssertionError("portable wheel byte-length mismatch")
    return artifact


def _validate_build_inputs(build_inputs: object) -> dict:
    if not isinstance(build_inputs, dict) or frozenset(build_inputs) != BUILD_INPUT_KEYS:
        raise AssertionError("unexpected build-input claim set")
    for name, digest in build_inputs.items():
        if not isinstance(name, str) or not _lower_hex(digest, 64):
            raise AssertionError(f"invalid build-input digest claim: {name!r}")
    return build_inputs


def _validate_provenance(provenance: dict, wheel: Path) -> None:
    if frozenset(provenance) != PROVENANCE_KEYS:
        raise AssertionError("unexpected portable provenance fields")
    if provenance["schema"] != PROVENANCE_SCHEMA:
        raise AssertionError("unexpected portable provenance schema")
    _validate_source(provenance["source"])
    if provenance["builder"] != BUILDER_POLICY:
        raise AssertionError("portable builder policy mismatch")
    _validate_artifact(provenance["artifact"], wheel)
    _validate_build_inputs(provenance["build_inputs"])
    if provenance["production_consensus"] != "python":
        raise AssertionError("unexpected production consensus authority")


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


def _verify(wheel: Path, provenance_path: Path, envelope_path: Path) -> tuple[str, str]:
    for path, label in (
        (wheel, "portable wheel"),
        (provenance_path, "portable provenance"),
        (envelope_path, "portable attestation envelope"),
    ):
        _assert_regular_file(path, label)
    resolved = {wheel.resolve(), provenance_path.resolve(), envelope_path.resolve()}
    if len(resolved) != 3:
        raise AssertionError("consumer inputs must be three distinct files")

    payload, provenance = _load_canonical_json(provenance_path, label="portable provenance")
    _validate_provenance(provenance, wheel)

    _, envelope = _load_canonical_json(envelope_path, label="portable attestation envelope")
    if frozenset(envelope) != ENVELOPE_KEYS:
        raise AssertionError("unexpected portable attestation envelope fields")
    expected_header = _header(payload)
    header = {name: envelope[name] for name in envelope if name != "signature"}
    if header != expected_header:
        raise AssertionError("portable attestation policy or payload digest mismatch")
    signature = _decode_signature(envelope["signature"])
    try:
        Ed25519PublicKey.from_public_bytes(PINNED_PUBLIC_KEY).verify(
            signature, _message(payload, expected_header)
        )
    except InvalidSignature as exc:
        raise AssertionError("portable attestation signature verification failed") from exc

    return provenance["artifact"]["sha256"], provenance["source"]["commit"]


def verify(wheel: Path, provenance_path: Path, envelope_path: Path) -> None:
    artifact_sha256, source_commit = _verify(wheel, provenance_path, envelope_path)
    print(
        "RUST-012 detached offline consumer verifier: GREEN "
        f"artifact_sha256={artifact_sha256} source={source_commit}"
    )


def _must_reject(wheel: Path, provenance: Path, envelope: Path, label: str) -> None:
    try:
        _verify(wheel, provenance, envelope)
    except (AssertionError, json.JSONDecodeError, UnicodeDecodeError):
        print(f"[GREEN] rejected {label}")
        return
    raise AssertionError(f"consumer mutation unexpectedly accepted: {label}")


def selftest(wheel: Path, provenance_path: Path, envelope_path: Path) -> None:
    verify(wheel, provenance_path, envelope_path)
    wheel_sha_before = _sha256_file(wheel)
    provenance_before = provenance_path.read_bytes()
    envelope_before = envelope_path.read_bytes()
    _, provenance = _load_canonical_json(provenance_path, label="portable provenance")
    _, envelope = _load_canonical_json(envelope_path, label="portable attestation envelope")
    checks = 0

    with tempfile.TemporaryDirectory(prefix="axven-rust012-") as temp:
        root = Path(temp)

        mutated_wheel = root / WHEEL_FILENAME
        mutated_wheel.write_bytes(wheel.read_bytes() + b"\x00")
        _must_reject(mutated_wheel, provenance_path, envelope_path, "wheel byte mutation")
        checks += 1

        renamed_wheel = root / "renamed.whl"
        renamed_wheel.write_bytes(wheel.read_bytes())
        _must_reject(renamed_wheel, provenance_path, envelope_path, "renamed wheel/path confusion")
        checks += 1

        p = root / "artifact-digest.json"
        mutated = copy.deepcopy(provenance)
        digest = mutated["artifact"]["sha256"]
        mutated["artifact"]["sha256"] = ("0" if digest[0] != "0" else "1") + digest[1:]
        p.write_bytes(_canonical(mutated))
        _must_reject(wheel, p, envelope_path, "artifact digest mutation")
        checks += 1

        p = root / "builder-image.json"
        mutated = copy.deepcopy(provenance)
        mutated["builder"]["image"] = "quay.io/pypa/manylinux_2_28_x86_64@sha256:" + "0" * 64
        p.write_bytes(_canonical(mutated))
        _must_reject(wheel, p, envelope_path, "builder-image substitution")
        checks += 1

        p = root / "source-repository.json"
        mutated = copy.deepcopy(provenance)
        mutated["source"]["repository"] = "attacker/example"
        p.write_bytes(_canonical(mutated))
        _must_reject(wheel, p, envelope_path, "source-repository substitution")
        checks += 1

        p = root / "unexpected-provenance-field.json"
        mutated = copy.deepcopy(provenance)
        mutated["public_key"] = PINNED_PUBLIC_KEY.hex()
        p.write_bytes(_canonical(mutated))
        _must_reject(wheel, p, envelope_path, "unexpected provenance field")
        checks += 1

        p = root / "noncanonical-provenance.json"
        p.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
        _must_reject(wheel, p, envelope_path, "non-canonical provenance")
        checks += 1

        e = root / "signature.json"
        mutated_envelope = copy.deepcopy(envelope)
        sig = bytearray(_decode_signature(mutated_envelope["signature"]))
        sig[0] ^= 0x01
        mutated_envelope["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        e.write_bytes(_canonical(mutated_envelope))
        _must_reject(wheel, provenance_path, e, "signature mutation")
        checks += 1

        e = root / "key-id.json"
        mutated_envelope = copy.deepcopy(envelope)
        mutated_envelope["key_id"] = "untrusted-key"
        e.write_bytes(_canonical(mutated_envelope))
        _must_reject(wheel, provenance_path, e, "key-id substitution")
        checks += 1

        e = root / "embedded-trust-root.json"
        mutated_envelope = copy.deepcopy(envelope)
        mutated_envelope["public_key"] = PINNED_PUBLIC_KEY.hex()
        e.write_bytes(_canonical(mutated_envelope))
        _must_reject(wheel, provenance_path, e, "embedded trust-root substitution")
        checks += 1

        e = root / "noncanonical-envelope.json"
        e.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
        _must_reject(wheel, provenance_path, e, "non-canonical envelope")
        checks += 1

    if checks != 11:
        raise AssertionError(checks)
    if _sha256_file(wheel) != wheel_sha_before:
        raise AssertionError("selftest mutated original wheel")
    if provenance_path.read_bytes() != provenance_before or envelope_path.read_bytes() != envelope_before:
        raise AssertionError("selftest mutated original evidence")
    verify(wheel, provenance_path, envelope_path)
    print("RUST-012 detached consumer fail-closed contract: 11/11 GREEN")


def main() -> None:
    if len(sys.argv) != 5 or sys.argv[1] not in {"verify", "selftest"}:
        raise SystemExit(
            "usage: rust_012_offline_consumer_verify.py {verify|selftest} "
            "WHEEL PROVENANCE ENVELOPE"
        )
    command = sys.argv[1]
    wheel = Path(sys.argv[2])
    provenance = Path(sys.argv[3])
    envelope = Path(sys.argv[4])
    if command == "verify":
        verify(wheel, provenance, envelope)
    else:
        selftest(wheel, provenance, envelope)


if __name__ == "__main__":
    main()
