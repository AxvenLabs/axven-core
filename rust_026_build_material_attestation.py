#!/usr/bin/env python3
"""RUST-026: TEST-ONLY signed build-material attestation and detached verifier."""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "axven-native-build-materials-v1"
ENVELOPE_SCHEMA = "axven-native-build-material-attestation-envelope-v1"
PAYLOAD_TYPE = "application/vnd.axven.native-build-materials.v1+json"
ALGORITHM = "ed25519"
KEY_ID = "rust-026-test-only-ed25519-v1"
DOMAIN = b"AXVEN_NATIVE_BUILD_MATERIAL_ATTESTATION_V1\x00"
TEST_SEED = bytes.fromhex("da8a182c808371700b7b10e9408ef5e97b62a9018a8426cfd489adcacc24a9aa")
PINNED_PUBLIC_KEY = bytes.fromhex("4dd000548d1ed66588e6c23531163bd12c9c5dbca5eb932d4c6a75cde6525064")
REPOSITORY = "AxvenLabs/axven-core"
WHEEL_FILENAME = "axven_native-0.1.0-cp313-abi3-manylinux_2_28_x86_64.whl"
RUST_URL = "https://static.rust-lang.org/dist/2026-08-20/rust-1.98.0-x86_64-unknown-linux-gnu.tar.xz"
RUST_SHA256 = "ed8ee2df70909c88cbaf87a6cfa3920dac00b537de12a6abe6906641e0f5952f"
RUST_ARCHIVE_NAME = "rust-1.98.0-x86_64-unknown-linux-gnu.tar.xz"
TOOLCHAIN_SCHEMA = "axven-rust-toolchain-closure-v1"
TOOLCHAIN_NAME = "1.98.0-x86_64-unknown-linux-gnu"
MANYLINUX_IMAGE = "quay.io/pypa/manylinux_2_28_x86_64@sha256:443eabd378e140996780a772e12c1a1ef10551da933fe76d74a1bab61f68a7b7"
HEX = frozenset("0123456789abcdef")

MATERIAL_KEYS = frozenset({"schema", "source", "builder", "artifact", "rust", "dependencies", "vendor", "production_consensus"})
SOURCE_KEYS = frozenset({"repository", "commit"})
BUILDER_KEYS = frozenset({"image", "python", "rust", "cargo", "maturin", "pyo3"})
ARTIFACT_KEYS = frozenset({"filename", "sha256", "bytes"})
RUST_KEYS = frozenset({"distribution_url", "distribution_filename", "distribution_sha256", "toolchain_manifest_sha256", "toolchain_manifest_bytes", "toolchain_file_count"})
DEPENDENCY_KEYS = frozenset({"cargo_lock_sha256", "native_build_lock_sha256", "closure_sha256", "file_count", "crate_count", "python_wheel_count"})
VENDOR_KEYS = frozenset({"closure_sha256", "file_count", "package_count"})
ENVELOPE_KEYS = frozenset({"schema", "algorithm", "key_id", "payload_type", "payload_sha256", "signature"})


def canonical(obj: object) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def lower_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(ch in HEX for ch in value)


def assert_regular(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise AssertionError(f"{label} must be a real regular file")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_rel(value: str) -> str:
    p = PurePosixPath(value)
    if not value or p.is_absolute() or "\\" in value or "\x00" in value:
        raise AssertionError(f"unsafe closure path: {value!r}")
    if any(part in {"", ".", ".."} for part in p.parts) or p.as_posix() != value:
        raise AssertionError(f"non-canonical closure path: {value!r}")
    return value


def inventory(root: Path, label: str) -> tuple[str, int]:
    if root.is_symlink() or not root.is_dir():
        raise AssertionError(f"{label} must be a real directory")
    rows: list[dict[str, object]] = []
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in dirs:
            p = current_path / name
            if p.is_symlink() or not p.is_dir():
                raise AssertionError(f"{label} contains unsafe directory entry")
        for name in files:
            p = current_path / name
            rel = safe_rel(p.relative_to(root).as_posix())
            if p.is_symlink():
                raise AssertionError(f"{label} contains symlink: {rel}")
            st = p.stat()
            if not stat.S_ISREG(st.st_mode):
                raise AssertionError(f"{label} contains unsupported file: {rel}")
            rows.append({"path": rel, "sha256": sha256_file(p), "bytes": st.st_size, "mode": stat.S_IMODE(st.st_mode)})
    rows.sort(key=lambda item: item["path"])
    if not rows:
        raise AssertionError(f"{label} is empty")
    if len({row["path"] for row in rows}) != len(rows):
        raise AssertionError(f"{label} duplicate path")
    return hashlib.sha256(canonical(rows)).hexdigest(), len(rows)


def load_canonical(path: Path, label: str) -> tuple[bytes, dict]:
    assert_regular(path, label)
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or raw != canonical(value):
        raise AssertionError(f"{label} must be canonical JSON object")
    return raw, value


def toolchain_manifest(path: Path) -> tuple[str, int, int]:
    raw, value = load_canonical(path, "toolchain manifest")
    if set(value) != {"schema", "toolchain", "file_count", "total_bytes", "files"}:
        raise AssertionError("unexpected toolchain manifest fields")
    if value["schema"] != TOOLCHAIN_SCHEMA or value["toolchain"] != TOOLCHAIN_NAME:
        raise AssertionError("unexpected toolchain manifest identity")
    count = value["file_count"]
    if type(count) is not int or count <= 0 or not isinstance(value["files"], list) or len(value["files"]) != count:
        raise AssertionError("invalid toolchain manifest count")
    return hashlib.sha256(raw).hexdigest(), len(raw), count


def actual_wheel(path: Path) -> dict:
    assert_regular(path, "wheel")
    if path.name != WHEEL_FILENAME:
        raise AssertionError("unexpected wheel filename")
    size = path.stat().st_size
    if size <= 0:
        raise AssertionError("empty wheel")
    return {"filename": path.name, "sha256": sha256_file(path), "bytes": size}


def actual_dependencies(root: Path, cargo_lock: Path, build_lock: Path) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise AssertionError("dependency closure must be a real directory")
    if {p.name for p in root.iterdir()} != {"cargo-crates", "python-wheels"}:
        raise AssertionError("unexpected dependency closure top-level entries")
    digest, count = inventory(root, "dependency closure")
    crates = sorted((root / "cargo-crates").glob("*.crate"))
    wheels = sorted((root / "python-wheels").glob("*.whl"))
    if len(crates) != 23 or len(wheels) != 1 or count != 24:
        raise AssertionError(f"unexpected dependency closure counts: crates={len(crates)} wheels={len(wheels)} files={count}")
    assert_regular(cargo_lock, "Cargo.lock")
    assert_regular(build_lock, "requirements-native-build.lock")
    return {"cargo_lock_sha256": sha256_file(cargo_lock), "native_build_lock_sha256": sha256_file(build_lock), "closure_sha256": digest, "file_count": count, "crate_count": len(crates), "python_wheel_count": len(wheels)}


def actual_vendor(root: Path) -> dict:
    digest, count = inventory(root, "vendor closure")
    packages = [p for p in root.iterdir() if p.is_dir() and not p.is_symlink()]
    if len(packages) != 23:
        raise AssertionError(f"unexpected vendor package count: {len(packages)}")
    return {"closure_sha256": digest, "file_count": count, "package_count": len(packages)}


def message(payload: bytes) -> bytes:
    return DOMAIN + len(payload).to_bytes(8, "big") + payload


def decode_signature(value: object) -> bytes:
    if not isinstance(value, str):
        raise AssertionError("signature must be base64")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise AssertionError("invalid base64 signature") from exc
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != value:
        raise AssertionError("invalid/non-canonical Ed25519 signature")
    return raw


def validate_materials(value: dict, expected_source_sha: str, wheel: dict, rust_archive: Path, toolchain: tuple[str, int, int], deps: dict, vendor: dict) -> None:
    if frozenset(value) != MATERIAL_KEYS or value["schema"] != SCHEMA:
        raise AssertionError("unexpected material schema/fields")
    source = value["source"]
    if not isinstance(source, dict) or frozenset(source) != SOURCE_KEYS:
        raise AssertionError("unexpected source fields")
    if source["repository"] != REPOSITORY or source["commit"] != expected_source_sha or not lower_hex(expected_source_sha, 40):
        raise AssertionError("source identity mismatch")
    builder = value["builder"]
    if not isinstance(builder, dict) or frozenset(builder) != BUILDER_KEYS:
        raise AssertionError("unexpected builder fields")
    expected_builder = {"image": MANYLINUX_IMAGE, "python": "3.13.13", "rust": "1.98.0", "cargo": "1.98.0", "maturin": "1.15.0", "pyo3": "0.29.2"}
    if builder != expected_builder:
        raise AssertionError("builder identity mismatch")
    artifact = value["artifact"]
    if not isinstance(artifact, dict) or frozenset(artifact) != ARTIFACT_KEYS or artifact != wheel:
        raise AssertionError("artifact identity mismatch")
    rust = value["rust"]
    if not isinstance(rust, dict) or frozenset(rust) != RUST_KEYS:
        raise AssertionError("unexpected Rust material fields")
    expected_rust = {"distribution_url": RUST_URL, "distribution_filename": RUST_ARCHIVE_NAME, "distribution_sha256": RUST_SHA256, "toolchain_manifest_sha256": toolchain[0], "toolchain_manifest_bytes": toolchain[1], "toolchain_file_count": toolchain[2]}
    assert_regular(rust_archive, "Rust archive")
    if rust_archive.name != RUST_ARCHIVE_NAME or sha256_file(rust_archive) != RUST_SHA256 or rust != expected_rust:
        raise AssertionError("Rust distribution/toolchain identity mismatch")
    dep = value["dependencies"]
    if not isinstance(dep, dict) or frozenset(dep) != DEPENDENCY_KEYS or dep != deps:
        raise AssertionError("dependency closure identity mismatch")
    vend = value["vendor"]
    if not isinstance(vend, dict) or frozenset(vend) != VENDOR_KEYS or vend != vendor:
        raise AssertionError("vendor closure identity mismatch")
    if value["production_consensus"] != "python-authoritative":
        raise AssertionError("unexpected production consensus claim")


def generate(wheel_path: Path, rust_archive: Path, toolchain_path: Path, dep_root: Path, vendor_root: Path, cargo_lock: Path, build_lock: Path, source_sha: str, output: Path) -> None:
    if not lower_hex(source_sha, 40):
        raise AssertionError("invalid source SHA")
    wheel = actual_wheel(wheel_path)
    toolchain = toolchain_manifest(toolchain_path)
    deps = actual_dependencies(dep_root, cargo_lock, build_lock)
    vendor = actual_vendor(vendor_root)
    value = {"schema": SCHEMA, "source": {"repository": REPOSITORY, "commit": source_sha}, "builder": {"image": MANYLINUX_IMAGE, "python": "3.13.13", "rust": "1.98.0", "cargo": "1.98.0", "maturin": "1.15.0", "pyo3": "0.29.2"}, "artifact": wheel, "rust": {"distribution_url": RUST_URL, "distribution_filename": RUST_ARCHIVE_NAME, "distribution_sha256": RUST_SHA256, "toolchain_manifest_sha256": toolchain[0], "toolchain_manifest_bytes": toolchain[1], "toolchain_file_count": toolchain[2]}, "dependencies": deps, "vendor": vendor, "production_consensus": "python-authoritative"}
    output.write_bytes(canonical(value))
    print(f"RUST-026 materials generated: wheel={wheel['sha256']} deps={deps['closure_sha256']} vendor={vendor['closure_sha256']}")


def seal(materials: Path, envelope: Path) -> None:
    raw, _ = load_canonical(materials, "materials")
    private = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    derived = private.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    if derived != PINNED_PUBLIC_KEY:
        raise AssertionError("RUST-026 TEST-ONLY key/public-key pin mismatch")
    sig = private.sign(message(raw))
    env = {"schema": ENVELOPE_SCHEMA, "algorithm": ALGORITHM, "key_id": KEY_ID, "payload_type": PAYLOAD_TYPE, "payload_sha256": hashlib.sha256(raw).hexdigest(), "signature": base64.b64encode(sig).decode("ascii")}
    envelope.write_bytes(canonical(env))
    print("RUST-026 TEST-ONLY build-material attestation sealed")


def verify(wheel_path: Path, rust_archive: Path, toolchain_path: Path, dep_root: Path, vendor_root: Path, cargo_lock: Path, build_lock: Path, source_sha: str, materials: Path, envelope: Path) -> None:
    raw, value = load_canonical(materials, "materials")
    _, env = load_canonical(envelope, "envelope")
    if frozenset(env) != ENVELOPE_KEYS:
        raise AssertionError("unexpected envelope fields")
    if env["schema"] != ENVELOPE_SCHEMA or env["algorithm"] != ALGORITHM or env["key_id"] != KEY_ID or env["payload_type"] != PAYLOAD_TYPE:
        raise AssertionError("unexpected envelope policy")
    if env["payload_sha256"] != hashlib.sha256(raw).hexdigest():
        raise AssertionError("payload SHA-256 mismatch")
    sig = decode_signature(env["signature"])
    try:
        Ed25519PublicKey.from_public_bytes(PINNED_PUBLIC_KEY).verify(sig, message(raw))
    except InvalidSignature as exc:
        raise AssertionError("RUST-026 attestation signature mismatch") from exc
    wheel = actual_wheel(wheel_path)
    toolchain = toolchain_manifest(toolchain_path)
    deps = actual_dependencies(dep_root, cargo_lock, build_lock)
    vend = actual_vendor(vendor_root)
    validate_materials(value, source_sha, wheel, rust_archive, toolchain, deps, vend)
    print(f"RUST-026 detached build-material attestation: GREEN source={source_sha} wheel={wheel['sha256']}")


def expect_failure(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] mutation rejected: {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def selftest(wheel_path: Path, rust_archive: Path, toolchain_path: Path, dep_root: Path, vendor_root: Path, cargo_lock: Path, build_lock: Path, source_sha: str, materials: Path, envelope: Path) -> None:
    verify(wheel_path, rust_archive, toolchain_path, dep_root, vendor_root, cargo_lock, build_lock, source_sha, materials, envelope)
    _, base = load_canonical(materials, "materials")
    _, base_env = load_canonical(envelope, "envelope")
    cases = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def resigned(mutator, name: str) -> None:
            nonlocal cases
            value = copy.deepcopy(base)
            mutator(value)
            m = root / f"{name}.json"
            e = root / f"{name}.envelope.json"
            m.write_bytes(canonical(value))
            seal(m, e)
            expect_failure(name, lambda: verify(wheel_path, rust_archive, toolchain_path, dep_root, vendor_root, cargo_lock, build_lock, source_sha, m, e))
            cases += 1

        resigned(lambda v: v["source"].__setitem__("commit", "0" * 40), "source-commit")
        resigned(lambda v: v["rust"].__setitem__("distribution_sha256", "0" * 64), "rust-distribution")
        resigned(lambda v: v["rust"].__setitem__("toolchain_manifest_sha256", "0" * 64), "toolchain-manifest")
        resigned(lambda v: v["dependencies"].__setitem__("closure_sha256", "0" * 64), "dependency-closure")
        resigned(lambda v: v["vendor"].__setitem__("closure_sha256", "0" * 64), "vendor-closure")
        resigned(lambda v: v["builder"].__setitem__("image", "invalid-image"), "builder-image")

        bad_env = copy.deepcopy(base_env)
        sig = bytearray(decode_signature(bad_env["signature"]))
        sig[0] ^= 1
        bad_env["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        bad_env_path = root / "bad-signature.json"
        bad_env_path.write_bytes(canonical(bad_env))
        expect_failure("signature", lambda: verify(wheel_path, rust_archive, toolchain_path, dep_root, vendor_root, cargo_lock, build_lock, source_sha, materials, bad_env_path))
        cases += 1

        noncanonical = root / "noncanonical.json"
        noncanonical.write_text(json.dumps(base, indent=2) + "\n", encoding="utf-8")
        expect_failure("noncanonical-materials", lambda: verify(wheel_path, rust_archive, toolchain_path, dep_root, vendor_root, cargo_lock, build_lock, source_sha, noncanonical, envelope))
        cases += 1

        bad_wheel = root / WHEEL_FILENAME
        payload = bytearray(wheel_path.read_bytes())
        payload[len(payload) // 2] ^= 1
        bad_wheel.write_bytes(bytes(payload))
        expect_failure("wheel-bytes", lambda: verify(bad_wheel, rust_archive, toolchain_path, dep_root, vendor_root, cargo_lock, build_lock, source_sha, materials, envelope))
        cases += 1

    assert cases == 9
    print("RUST-026 build-material attestation mutation contract: 9/9 expected cases passed")


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: rust_026_build_material_attestation.py generate|seal|verify|selftest ...")
    cmd = sys.argv[1]
    if cmd == "generate" and len(sys.argv) == 11:
        generate(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), Path(sys.argv[6]), Path(sys.argv[7]), Path(sys.argv[8]), sys.argv[9], Path(sys.argv[10]))
    elif cmd == "seal" and len(sys.argv) == 4:
        seal(Path(sys.argv[2]), Path(sys.argv[3]))
    elif cmd in {"verify", "selftest"} and len(sys.argv) == 12:
        args = (Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), Path(sys.argv[6]), Path(sys.argv[7]), Path(sys.argv[8]), sys.argv[9], Path(sys.argv[10]), Path(sys.argv[11]))
        (verify if cmd == "verify" else selftest)(*args)
    else:
        raise SystemExit("invalid RUST-026 command/arguments")


if __name__ == "__main__":
    main()
