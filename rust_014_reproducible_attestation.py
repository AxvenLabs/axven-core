#!/usr/bin/env python3
"""RUST-014: bind RUST-013 reproducibility evidence into TEST-ONLY signed provenance."""
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
WHEELHOUSE_A = ROOT / "wheelhouse-repro-a"
WHEELHOUSE_B = ROOT / "wheelhouse-repro-b"

PROVENANCE_SCHEMA = "axven-native-reproducible-provenance-v1"
ATTESTATION_SCHEMA = "axven-native-reproducible-attestation-envelope-v1"
PAYLOAD_TYPE = "application/vnd.axven.native-reproducible-provenance.v1+json"
ALGORITHM = "ed25519"
KEY_ID = "rust-014-test-only-ed25519-v1"
DOMAIN = b"AXVEN_NATIVE_REPRODUCIBLE_ATTESTATION_V1\x00"

BUILDER_PYTHON = "3.13.13"
RUST_VERSION = "1.98.0"
MATURIN_VERSION = "1.15.0"
PYO3_VERSION = "0.29.2"
EXPECTED_WHEEL = "axven_native-0.1.0-cp313-abi3-manylinux_2_28_x86_64.whl"
MANYLINUX_IMAGE = (
    "quay.io/pypa/manylinux_2_28_x86_64@"
    "sha256:443eabd378e140996780a772e12c1a1ef10551da933fe76d74a1bab61f68a7b7"
)
TEST_SEED = bytes.fromhex("c11e21c4973ab83d909eaf2798e1587340521b36eda40c442234997c49a3aecd")
PINNED_PUBLIC_KEY = bytes.fromhex("530bca4775ffd53881935dc81738f6e4f37b1b9dcda1129fdbd7005692907c1a")
HEX = frozenset("0123456789abcdef")

BUILD_INPUTS = (
    "native/axven_native/Cargo.toml",
    "native/axven_native/Cargo.lock",
    "native/axven_native/src/lib.rs",
    "requirements-native-build.lock",
    "requirements-ci-runtime-posix.lock",
    "rust_009_portable_linux_wheel_spec.py",
    "rust_013_reproducible_wheel_spec.py",
    "rust_013_reproducible_build_policy_spec.py",
    "rust_014_reproducible_attestation.py",
    "rust_014_reproducible_attestation_policy_spec.py",
    ".github/workflows/native-reproducible-build.yml",
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


def _source_identity() -> tuple[dict, int]:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    source_sha = os.environ.get("AXVEN_SOURCE_SHA", "").lower()
    epoch_text = os.environ.get("SOURCE_DATE_EPOCH", "")
    if repository != "AxvenLabs/axven-core":
        raise AssertionError(f"unexpected repository: {repository!r}")
    if not _lower_hex(source_sha, 40):
        raise AssertionError(f"invalid source sha: {source_sha!r}")
    if not epoch_text.isdigit():
        raise AssertionError(f"invalid SOURCE_DATE_EPOCH: {epoch_text!r}")
    epoch = int(epoch_text)
    if epoch < 315532800:
        raise AssertionError(f"SOURCE_DATE_EPOCH predates ZIP-safe policy floor: {epoch}")

    checkout_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, encoding="utf-8"
    ).strip().lower()
    if checkout_sha != source_sha:
        raise AssertionError((checkout_sha, source_sha))
    commit_epoch = subprocess.check_output(
        ["git", "show", "-s", "--format=%ct", source_sha],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
    ).strip()
    if not commit_epoch.isdigit() or int(commit_epoch) != epoch:
        raise AssertionError((commit_epoch, epoch))
    return {"repository": repository, "commit": source_sha}, epoch


def _single_wheel(directory: Path) -> Path:
    if directory.is_symlink() or not directory.is_dir():
        raise AssertionError(f"wheelhouse must be a real directory: {directory}")
    wheels = sorted(directory.glob("*.whl"))
    if len(wheels) != 1:
        raise AssertionError(f"expected exactly one wheel in {directory}, got {wheels!r}")
    wheel = wheels[0]
    if wheel.is_symlink() or not wheel.is_file():
        raise AssertionError(f"wheel must be a regular non-symlink file: {wheel}")
    if wheel.name != EXPECTED_WHEEL:
        raise AssertionError(f"unexpected wheel filename: {wheel.name}")
    if wheel.stat().st_size <= 0:
        raise AssertionError("empty wheel")
    return wheel


def _reproducible_artifact() -> tuple[dict, dict]:
    left = _single_wheel(WHEELHOUSE_A)
    right = _single_wheel(WHEELHOUSE_B)
    left_sha = _sha256_file(left)
    right_sha = _sha256_file(right)
    left_size = left.stat().st_size
    right_size = right.stat().st_size
    if left_sha != right_sha or left_size != right_size:
        raise AssertionError((left_sha, left_size, right_sha, right_size))
    if left.read_bytes() != right.read_bytes():
        raise AssertionError("RUST-014 requires byte-identical build A/B wheels")
    artifact = {"filename": EXPECTED_WHEEL, "sha256": left_sha, "bytes": left_size}
    evidence = {
        "build_count": 2,
        "byte_identical": True,
        "build_a": {"sha256": left_sha, "bytes": left_size},
        "build_b": {"sha256": right_sha, "bytes": right_size},
    }
    return artifact, evidence


def _build_inputs() -> dict:
    result: dict[str, str] = {}
    for relative in BUILD_INPUTS:
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            raise AssertionError(f"build input must be a regular repository file: {relative}")
        digest = _sha256_file(path)
        if not _lower_hex(digest, 64):
            raise AssertionError((relative, digest))
        result[relative] = digest
    return result


def _expected_provenance() -> dict:
    image = os.environ.get("MANYLINUX_IMAGE", "")
    if image != MANYLINUX_IMAGE:
        raise AssertionError(f"unexpected manylinux image: {image!r}")
    source, epoch = _source_identity()
    artifact, evidence = _reproducible_artifact()
    return {
        "schema": PROVENANCE_SCHEMA,
        "source": source,
        "source_date_epoch": epoch,
        "builder": {
            "image": MANYLINUX_IMAGE,
            "compatibility": "manylinux_2_28",
            "architecture": "x86_64",
            "python": BUILDER_PYTHON,
            "rust": RUST_VERSION,
            "maturin": MATURIN_VERSION,
            "pyo3": PYO3_VERSION,
            "deterministic_environment": {
                "CARGO_INCREMENTAL": "0",
                "PYTHONHASHSEED": "0",
                "TZ": "UTC",
                "LC_ALL": "C.UTF-8",
            },
        },
        "artifact": artifact,
        "reproducibility": evidence,
        "build_inputs": _build_inputs(),
        "production_consensus": "python",
    }


def generate(provenance_path: Path) -> None:
    provenance = _expected_provenance()
    provenance_path.write_bytes(_canonical(provenance))
    print(
        "RUST-014 reproducibility provenance generated "
        f"artifact_sha256={provenance['artifact']['sha256']} "
        f"source={provenance['source']['commit']} epoch={provenance['source_date_epoch']}"
    )


def _load_provenance(provenance_path: Path) -> tuple[bytes, dict]:
    raw, loaded = _load_canonical_json(provenance_path, label="RUST-014 reproducibility provenance")
    if loaded != _expected_provenance():
        raise AssertionError("RUST-014 provenance does not match current source/build/reproducibility evidence")
    return raw, loaded


def _private_key() -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    derived = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if derived != PINNED_PUBLIC_KEY:
        raise AssertionError("RUST-014 pinned TEST-ONLY key mismatch")
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
    print(f"RUST-014 TEST-ONLY reproducibility attestation sealed payload_sha256={header['payload_sha256']}")


def verify(provenance_path: Path, envelope_path: Path) -> None:
    payload, _ = _load_provenance(provenance_path)
    _, envelope = _load_canonical_json(envelope_path, label="RUST-014 attestation envelope")
    if frozenset(envelope) != ENVELOPE_KEYS:
        raise AssertionError("unexpected RUST-014 attestation envelope fields")
    header = {name: envelope[name] for name in envelope if name != "signature"}
    if header != _header(payload):
        raise AssertionError("RUST-014 attestation policy or payload digest mismatch")
    signature = _decode_signature(envelope.get("signature"))
    public_key = Ed25519PublicKey.from_public_bytes(PINNED_PUBLIC_KEY)
    try:
        public_key.verify(signature, _message(payload, header))
    except InvalidSignature as exc:
        raise AssertionError("RUST-014 attestation signature verification failed") from exc
    print(f"RUST-014 reproducibility-bound attestation: GREEN payload_sha256={header['payload_sha256']}")


def _must_reject(provenance: Path, envelope: Path, label: str) -> None:
    try:
        verify(provenance, envelope)
    except (AssertionError, json.JSONDecodeError, UnicodeDecodeError):
        print(f"[GREEN] rejected {label}")
        return
    raise AssertionError(f"tamper case unexpectedly accepted: {label}")


def selftest(provenance_path: Path, envelope_path: Path) -> None:
    verify(provenance_path, envelope_path)
    payload_raw, payload = _load_canonical_json(provenance_path, label="RUST-014 provenance")
    envelope_raw, envelope = _load_canonical_json(envelope_path, label="RUST-014 envelope")

    with tempfile.TemporaryDirectory(prefix="axven-rust014-") as temp:
        root = Path(temp)

        artifact_tamper = copy.deepcopy(payload)
        digest = artifact_tamper["artifact"]["sha256"]
        artifact_tamper["artifact"]["sha256"] = ("0" if digest[0] != "0" else "1") + digest[1:]
        p = root / "artifact-tamper.json"
        p.write_bytes(_canonical(artifact_tamper))
        _must_reject(p, envelope_path, "artifact digest mutation")

        epoch_tamper = copy.deepcopy(payload)
        epoch_tamper["source_date_epoch"] += 2
        p = root / "epoch-tamper.json"
        p.write_bytes(_canonical(epoch_tamper))
        _must_reject(p, envelope_path, "reproducibility epoch mutation")

        build_b_tamper = copy.deepcopy(payload)
        digest = build_b_tamper["reproducibility"]["build_b"]["sha256"]
        build_b_tamper["reproducibility"]["build_b"]["sha256"] = ("0" if digest[0] != "0" else "1") + digest[1:]
        p = root / "build-b-tamper.json"
        p.write_bytes(_canonical(build_b_tamper))
        _must_reject(p, envelope_path, "build-B evidence digest mutation")

        builder_tamper = copy.deepcopy(payload)
        builder_tamper["builder"]["image"] = (
            "quay.io/pypa/manylinux_2_28_x86_64@sha256:" + "0" * 64
        )
        p = root / "builder-tamper.json"
        p.write_bytes(_canonical(builder_tamper))
        _must_reject(p, envelope_path, "builder image mutation")

        signature_tamper = copy.deepcopy(envelope)
        sig = bytearray(_decode_signature(signature_tamper["signature"]))
        sig[0] ^= 0x01
        signature_tamper["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        e = root / "signature-tamper.json"
        e.write_bytes(_canonical(signature_tamper))
        _must_reject(provenance_path, e, "signature mutation")

        key_tamper = copy.deepcopy(envelope)
        key_tamper["key_id"] = "untrusted-key"
        e = root / "key-tamper.json"
        e.write_bytes(_canonical(key_tamper))
        _must_reject(provenance_path, e, "key-id substitution")

        trust_root_tamper = copy.deepcopy(envelope)
        trust_root_tamper["public_key"] = PINNED_PUBLIC_KEY.hex()
        e = root / "trust-root-tamper.json"
        e.write_bytes(_canonical(trust_root_tamper))
        _must_reject(provenance_path, e, "embedded trust-root substitution")

        noncanonical = root / "noncanonical-envelope.json"
        noncanonical.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
        _must_reject(provenance_path, noncanonical, "non-canonical envelope")

    if payload_raw != provenance_path.read_bytes() or envelope_raw != envelope_path.read_bytes():
        raise AssertionError("RUST-014 selftest mutated source evidence")
    verify(provenance_path, envelope_path)
    print("RUST-014 fail-closed mutation contract: 8/8 GREEN")


def main() -> None:
    if len(sys.argv) < 3:
        raise SystemExit(
            "usage: rust_014_reproducible_attestation.py generate PROVENANCE | "
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
        "usage: rust_014_reproducible_attestation.py generate PROVENANCE | "
        "{seal|verify|selftest} PROVENANCE ENVELOPE"
    )


if __name__ == "__main__":
    main()
