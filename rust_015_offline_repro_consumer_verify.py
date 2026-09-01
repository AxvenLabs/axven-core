#!/usr/bin/env python3
"""RUST-015: detached offline verifier for RUST-014 reproducibility evidence."""
from __future__ import annotations

import base64
import binascii
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import tempfile
import zipfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROVENANCE_SCHEMA = "axven-native-reproducible-provenance-v1"
ATTESTATION_SCHEMA = "axven-native-reproducible-attestation-envelope-v1"
PAYLOAD_TYPE = "application/vnd.axven.native-reproducible-provenance.v1+json"
ALGORITHM = "ed25519"
KEY_ID = "rust-014-test-only-ed25519-v1"
DOMAIN = b"AXVEN_NATIVE_REPRODUCIBLE_ATTESTATION_V1\x00"
PINNED_PUBLIC_KEY = bytes.fromhex("530bca4775ffd53881935dc81738f6e4f37b1b9dcda1129fdbd7005692907c1a")
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
    "deterministic_environment": {
        "CARGO_INCREMENTAL": "0",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
        "LC_ALL": "C.UTF-8",
    },
}
BUILD_INPUT_KEYS = frozenset(
    {
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
    }
)
PROVENANCE_KEYS = frozenset(
    {
        "schema",
        "source",
        "source_date_epoch",
        "builder",
        "artifact",
        "reproducibility",
        "build_inputs",
        "production_consensus",
    }
)
SOURCE_KEYS = frozenset({"repository", "commit"})
ARTIFACT_KEYS = frozenset({"filename", "sha256", "bytes"})
REPRO_KEYS = frozenset({"build_count", "byte_identical", "build_a", "build_b"})
BUILD_EVIDENCE_KEYS = frozenset({"sha256", "bytes"})
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


def _expected_zip_time(epoch: int) -> tuple[int, int, int, int, int, int]:
    stamp = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return (
        stamp.year,
        stamp.month,
        stamp.day,
        stamp.hour,
        stamp.minute,
        stamp.second - stamp.second % 2,
    )


def _member_policy(info: zipfile.ZipInfo) -> None:
    name = info.filename
    if not name or name.startswith("/") or "\\" in name:
        raise AssertionError(f"unsafe wheel member: {name!r}")
    parts = PurePosixPath(name).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise AssertionError(f"unsafe wheel member path: {name!r}")


def _validate_wheel_zip(path: Path, epoch: int) -> None:
    expected_time = _expected_zip_time(epoch)
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise AssertionError("wheel ZIP integrity check failed")
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if not names or len(names) != len(set(names)):
            raise AssertionError("empty or duplicate wheel member set")
        for info in infos:
            _member_policy(info)
            if info.date_time != expected_time:
                raise AssertionError(
                    f"wheel ZIP timestamp mismatch for {info.filename}: {info.date_time} != {expected_time}"
                )
        native = [name for name in names if name.endswith(".so")]
        records = [name for name in names if name.endswith(".dist-info/RECORD")]
        wheel_meta = [name for name in names if name.endswith(".dist-info/WHEEL")]
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(native) != 1 or len(records) != 1 or len(wheel_meta) != 1 or len(metadata) != 1:
            raise AssertionError("unexpected portable wheel structure")


def _validate_source(source: object) -> None:
    if not isinstance(source, dict) or frozenset(source) != SOURCE_KEYS:
        raise AssertionError("unexpected source identity fields")
    if source["repository"] != REPOSITORY:
        raise AssertionError("unexpected source repository")
    if not _lower_hex(source["commit"], 40):
        raise AssertionError("invalid source commit claim")


def _validate_build_inputs(build_inputs: object) -> None:
    if not isinstance(build_inputs, dict) or frozenset(build_inputs) != BUILD_INPUT_KEYS:
        raise AssertionError("unexpected build-input claim set")
    for name, digest in build_inputs.items():
        if not isinstance(name, str) or not _lower_hex(digest, 64):
            raise AssertionError(f"invalid build-input digest claim: {name!r}")


def _actual_wheel(path: Path, label: str) -> dict:
    _assert_regular_file(path, label)
    if path.name != WHEEL_FILENAME:
        raise AssertionError(f"{label} filename/path binding mismatch")
    size = path.stat().st_size
    if size <= 0:
        raise AssertionError(f"{label} is empty")
    return {"sha256": _sha256_file(path), "bytes": size}


def _validate_artifact(artifact: object, actual_a: dict, actual_b: dict) -> None:
    if not isinstance(artifact, dict) or frozenset(artifact) != ARTIFACT_KEYS:
        raise AssertionError("unexpected artifact fields")
    if artifact["filename"] != WHEEL_FILENAME:
        raise AssertionError("unexpected artifact filename")
    if not _lower_hex(artifact["sha256"], 64):
        raise AssertionError("invalid artifact SHA-256 claim")
    if type(artifact["bytes"]) is not int or artifact["bytes"] <= 0:
        raise AssertionError("invalid artifact byte-length claim")
    expected = {"sha256": artifact["sha256"], "bytes": artifact["bytes"]}
    if actual_a != expected or actual_b != expected:
        raise AssertionError("artifact claim does not match both supplied wheels")


def _validate_build_evidence(value: object, actual: dict, label: str) -> None:
    if not isinstance(value, dict) or frozenset(value) != BUILD_EVIDENCE_KEYS:
        raise AssertionError(f"unexpected {label} evidence fields")
    if not _lower_hex(value["sha256"], 64):
        raise AssertionError(f"invalid {label} SHA-256 claim")
    if type(value["bytes"]) is not int or value["bytes"] <= 0:
        raise AssertionError(f"invalid {label} byte-length claim")
    if value != actual:
        raise AssertionError(f"{label} evidence mismatch")


def _validate_reproducibility(value: object, actual_a: dict, actual_b: dict) -> None:
    if not isinstance(value, dict) or frozenset(value) != REPRO_KEYS:
        raise AssertionError("unexpected reproducibility fields")
    if type(value["build_count"]) is not int or value["build_count"] != 2:
        raise AssertionError("reproducibility build_count must be exactly 2")
    if value["byte_identical"] is not True:
        raise AssertionError("reproducibility byte_identical must be true")
    _validate_build_evidence(value["build_a"], actual_a, "build-A")
    _validate_build_evidence(value["build_b"], actual_b, "build-B")


def _validate_provenance(provenance: dict, wheel_a: Path, wheel_b: Path) -> None:
    if frozenset(provenance) != PROVENANCE_KEYS:
        raise AssertionError("unexpected reproducibility provenance fields")
    if provenance["schema"] != PROVENANCE_SCHEMA:
        raise AssertionError("unexpected reproducibility provenance schema")
    _validate_source(provenance["source"])
    epoch = provenance["source_date_epoch"]
    if type(epoch) is not int or epoch < 315532800:
        raise AssertionError("invalid source_date_epoch claim")
    if provenance["builder"] != BUILDER_POLICY:
        raise AssertionError("reproducible builder policy mismatch")

    actual_a = _actual_wheel(wheel_a, "build-A wheel")
    actual_b = _actual_wheel(wheel_b, "build-B wheel")
    if wheel_a.resolve() == wheel_b.resolve():
        raise AssertionError("build A and build B must resolve to distinct wheel paths")
    if actual_a != actual_b or wheel_a.read_bytes() != wheel_b.read_bytes():
        raise AssertionError("supplied build A/B wheels are not byte-for-byte identical")
    _validate_wheel_zip(wheel_a, epoch)
    _validate_wheel_zip(wheel_b, epoch)
    _validate_artifact(provenance["artifact"], actual_a, actual_b)
    _validate_reproducibility(provenance["reproducibility"], actual_a, actual_b)
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


def _verify(wheel_a: Path, wheel_b: Path, provenance_path: Path, envelope_path: Path) -> tuple[str, str]:
    for path, label in (
        (wheel_a, "build-A wheel"),
        (wheel_b, "build-B wheel"),
        (provenance_path, "reproducibility provenance"),
        (envelope_path, "reproducibility attestation envelope"),
    ):
        _assert_regular_file(path, label)
    resolved = {wheel_a.resolve(), wheel_b.resolve(), provenance_path.resolve(), envelope_path.resolve()}
    if len(resolved) != 4:
        raise AssertionError("consumer evidence inputs must be four distinct files")

    payload, provenance = _load_canonical_json(provenance_path, label="reproducibility provenance")
    _validate_provenance(provenance, wheel_a, wheel_b)

    _, envelope = _load_canonical_json(envelope_path, label="reproducibility attestation envelope")
    if frozenset(envelope) != ENVELOPE_KEYS:
        raise AssertionError("unexpected reproducibility attestation envelope fields")
    expected_header = _header(payload)
    header = {name: envelope[name] for name in envelope if name != "signature"}
    if header != expected_header:
        raise AssertionError("reproducibility attestation policy or payload digest mismatch")
    signature = _decode_signature(envelope["signature"])
    try:
        Ed25519PublicKey.from_public_bytes(PINNED_PUBLIC_KEY).verify(
            signature, _message(payload, expected_header)
        )
    except InvalidSignature as exc:
        raise AssertionError("reproducibility attestation signature verification failed") from exc
    return provenance["artifact"]["sha256"], provenance["source"]["commit"]


def verify(wheel_a: Path, wheel_b: Path, provenance_path: Path, envelope_path: Path) -> None:
    artifact_sha, source = _verify(wheel_a, wheel_b, provenance_path, envelope_path)
    print(
        "RUST-015 detached offline reproducibility consumer: GREEN "
        f"artifact_sha256={artifact_sha} source={source}"
    )


def _must_reject(wheel_a: Path, wheel_b: Path, provenance: Path, envelope: Path, label: str) -> None:
    try:
        _verify(wheel_a, wheel_b, provenance, envelope)
    except (AssertionError, json.JSONDecodeError, UnicodeDecodeError, zipfile.BadZipFile):
        print(f"[GREEN] rejected {label}")
        return
    raise AssertionError(f"consumer mutation unexpectedly accepted: {label}")


def selftest(wheel_a: Path, wheel_b: Path, provenance_path: Path, envelope_path: Path) -> None:
    verify(wheel_a, wheel_b, provenance_path, envelope_path)
    sha_a_before = _sha256_file(wheel_a)
    sha_b_before = _sha256_file(wheel_b)
    provenance_before = provenance_path.read_bytes()
    envelope_before = envelope_path.read_bytes()
    _, provenance = _load_canonical_json(provenance_path, label="reproducibility provenance")
    _, envelope = _load_canonical_json(envelope_path, label="reproducibility envelope")
    checks = 0

    with tempfile.TemporaryDirectory(prefix="axven-rust015-") as temp:
        root = Path(temp)

        mutated_b = root / WHEEL_FILENAME
        mutated_b.write_bytes(wheel_b.read_bytes() + b"\x00")
        _must_reject(wheel_a, mutated_b, provenance_path, envelope_path, "build-B wheel byte mutation")
        checks += 1

        renamed_a = root / "renamed.whl"
        renamed_a.write_bytes(wheel_a.read_bytes())
        _must_reject(renamed_a, wheel_b, provenance_path, envelope_path, "renamed build-A wheel/path confusion")
        checks += 1

        p = root / "artifact-digest.json"
        mutated = copy.deepcopy(provenance)
        digest = mutated["artifact"]["sha256"]
        mutated["artifact"]["sha256"] = ("0" if digest[0] != "0" else "1") + digest[1:]
        p.write_bytes(_canonical(mutated))
        _must_reject(wheel_a, wheel_b, p, envelope_path, "artifact digest mutation")
        checks += 1

        p = root / "epoch.json"
        mutated = copy.deepcopy(provenance)
        mutated["source_date_epoch"] += 2
        p.write_bytes(_canonical(mutated))
        _must_reject(wheel_a, wheel_b, p, envelope_path, "source epoch mutation")
        checks += 1

        p = root / "byte-identical.json"
        mutated = copy.deepcopy(provenance)
        mutated["reproducibility"]["byte_identical"] = False
        p.write_bytes(_canonical(mutated))
        _must_reject(wheel_a, wheel_b, p, envelope_path, "byte-identical claim substitution")
        checks += 1

        p = root / "build-input-set.json"
        mutated = copy.deepcopy(provenance)
        del mutated["build_inputs"][sorted(BUILD_INPUT_KEYS)[0]]
        p.write_bytes(_canonical(mutated))
        _must_reject(wheel_a, wheel_b, p, envelope_path, "build-input claim-set mutation")
        checks += 1

        p = root / "builder-image.json"
        mutated = copy.deepcopy(provenance)
        mutated["builder"]["image"] = "quay.io/pypa/manylinux_2_28_x86_64@sha256:" + "0" * 64
        p.write_bytes(_canonical(mutated))
        _must_reject(wheel_a, wheel_b, p, envelope_path, "builder-image substitution")
        checks += 1

        p = root / "unexpected-field.json"
        mutated = copy.deepcopy(provenance)
        mutated["public_key"] = PINNED_PUBLIC_KEY.hex()
        p.write_bytes(_canonical(mutated))
        _must_reject(wheel_a, wheel_b, p, envelope_path, "unexpected provenance field / trust-root injection")
        checks += 1

        p = root / "noncanonical-provenance.json"
        p.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
        _must_reject(wheel_a, wheel_b, p, envelope_path, "non-canonical provenance")
        checks += 1

        e = root / "signature.json"
        mutated_envelope = copy.deepcopy(envelope)
        sig = bytearray(_decode_signature(mutated_envelope["signature"]))
        sig[0] ^= 0x01
        mutated_envelope["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        e.write_bytes(_canonical(mutated_envelope))
        _must_reject(wheel_a, wheel_b, provenance_path, e, "signature mutation")
        checks += 1

        e = root / "key-id.json"
        mutated_envelope = copy.deepcopy(envelope)
        mutated_envelope["key_id"] = "untrusted-key"
        e.write_bytes(_canonical(mutated_envelope))
        _must_reject(wheel_a, wheel_b, provenance_path, e, "key-id substitution")
        checks += 1

        e = root / "embedded-trust-root.json"
        mutated_envelope = copy.deepcopy(envelope)
        mutated_envelope["public_key"] = PINNED_PUBLIC_KEY.hex()
        e.write_bytes(_canonical(mutated_envelope))
        _must_reject(wheel_a, wheel_b, provenance_path, e, "embedded envelope trust-root substitution")
        checks += 1

        e = root / "noncanonical-envelope.json"
        e.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
        _must_reject(wheel_a, wheel_b, provenance_path, e, "non-canonical envelope")
        checks += 1

    if checks != 13:
        raise AssertionError(checks)
    if _sha256_file(wheel_a) != sha_a_before or _sha256_file(wheel_b) != sha_b_before:
        raise AssertionError("selftest mutated original wheels")
    if provenance_path.read_bytes() != provenance_before or envelope_path.read_bytes() != envelope_before:
        raise AssertionError("selftest mutated original evidence")
    verify(wheel_a, wheel_b, provenance_path, envelope_path)
    print("RUST-015 detached reproducibility fail-closed contract: 13/13 GREEN")


def main() -> None:
    if len(sys.argv) != 6 or sys.argv[1] not in {"verify", "selftest"}:
        raise SystemExit(
            "usage: rust_015_offline_repro_consumer_verify.py {verify|selftest} "
            "WHEEL_A WHEEL_B PROVENANCE ENVELOPE"
        )
    command = sys.argv[1]
    wheel_a = Path(sys.argv[2])
    wheel_b = Path(sys.argv[3])
    provenance = Path(sys.argv[4])
    envelope = Path(sys.argv[5])
    if command == "verify":
        verify(wheel_a, wheel_b, provenance, envelope)
    else:
        selftest(wheel_a, wheel_b, provenance, envelope)


if __name__ == "__main__":
    main()
