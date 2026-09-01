#!/usr/bin/env python3
"""RUST-028: stdlib-only detached verifier for RUST-026 build materials."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile

SCHEMA = "axven-native-build-materials-v1"
ENVELOPE_SCHEMA = "axven-native-build-material-attestation-envelope-v1"
PAYLOAD_TYPE = "application/vnd.axven.native-build-materials.v1+json"
ALGORITHM = "ed25519"
KEY_ID = "rust-026-test-only-ed25519-v1"
DOMAIN = b"AXVEN_NATIVE_BUILD_MATERIAL_ATTESTATION_V1\x00"
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

# RFC 8032 / Ed25519 constants.
FIELD_Q = 2**255 - 19
GROUP_L = 2**252 + 27742317777372353535851937790883648493
CURVE_D = (-121665 * pow(121666, FIELD_Q - 2, FIELD_Q)) % FIELD_Q
SQRT_M1 = pow(2, (FIELD_Q - 1) // 4, FIELD_Q)
IDENTITY = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> int:
    if y >= FIELD_Q:
        raise AssertionError("non-canonical Ed25519 y coordinate")
    x2 = ((y * y - 1) * pow((CURVE_D * y * y + 1) % FIELD_Q, FIELD_Q - 2, FIELD_Q)) % FIELD_Q
    x = pow(x2, (FIELD_Q + 3) // 8, FIELD_Q)
    if (x * x - x2) % FIELD_Q:
        x = (x * SQRT_M1) % FIELD_Q
    if (x * x - x2) % FIELD_Q:
        raise AssertionError("invalid Ed25519 point")
    if x == 0 and sign:
        raise AssertionError("non-canonical Ed25519 negative zero")
    if (x & 1) != sign:
        x = FIELD_Q - x
    return x


def _decode_point(encoded: bytes) -> tuple[int, int, int, int]:
    if len(encoded) != 32:
        raise AssertionError("invalid Ed25519 point length")
    raw = int.from_bytes(encoded, "little")
    sign = (raw >> 255) & 1
    y = raw & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if (-x * x + y * y - 1 - CURVE_D * x * x * y * y) % FIELD_Q:
        raise AssertionError("Ed25519 point is off curve")
    return (x, y, 1, (x * y) % FIELD_Q)


def _add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % FIELD_Q
    b = ((y1 + x1) * (y2 + x2)) % FIELD_Q
    c = (2 * CURVE_D * t1 * t2) % FIELD_Q
    d = (2 * z1 * z2) % FIELD_Q
    e = (b - a) % FIELD_Q
    f = (d - c) % FIELD_Q
    g = (d + c) % FIELD_Q
    h = (b + a) % FIELD_Q
    return (e * f % FIELD_Q, g * h % FIELD_Q, f * g % FIELD_Q, e * h % FIELD_Q)


def _scalar_mult(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def _points_equal(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % FIELD_Q == 0 and (y1 * z2 - y2 * z1) % FIELD_Q == 0


_BASE_Y = (4 * pow(5, FIELD_Q - 2, FIELD_Q)) % FIELD_Q
_BASE_X = _recover_x(_BASE_Y, 0)
BASE_POINT = (_BASE_X, _BASE_Y, 1, (_BASE_X * _BASE_Y) % FIELD_Q)


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> None:
    if len(public_key) != 32 or len(signature) != 64:
        raise AssertionError("invalid Ed25519 key/signature length")
    a = _decode_point(public_key)
    r = _decode_point(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if s >= GROUP_L:
        raise AssertionError("non-canonical Ed25519 S scalar")
    k = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % GROUP_L
    if not _points_equal(_scalar_mult(BASE_POINT, s), _add(r, _scalar_mult(a, k))):
        raise AssertionError("Ed25519 signature mismatch")


def rfc8032_selftest() -> None:
    public_key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    ed25519_verify(public_key, signature, b"")
    mutated = bytearray(signature)
    mutated[0] ^= 1
    try:
        ed25519_verify(public_key, bytes(mutated), b"")
    except AssertionError:
        print("RUST-028 RFC 8032 Ed25519 vector: GREEN")
        return
    raise AssertionError("mutated RFC 8032 signature unexpectedly accepted")


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


def load_canonical(path: Path, label: str) -> tuple[bytes, dict]:
    assert_regular(path, label)
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or raw != canonical(value):
        raise AssertionError(f"{label} must be canonical JSON object")
    return raw, value


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
    if not rows or len({row["path"] for row in rows}) != len(rows):
        raise AssertionError(f"{label} empty/duplicate inventory")
    return hashlib.sha256(canonical(rows)).hexdigest(), len(rows)


def actual_wheel(path: Path) -> dict:
    assert_regular(path, "wheel")
    if path.name != WHEEL_FILENAME:
        raise AssertionError("unexpected wheel filename")
    size = path.stat().st_size
    if size <= 0:
        raise AssertionError("empty wheel")
    return {"filename": path.name, "sha256": sha256_file(path), "bytes": size}


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


def actual_dependencies(root: Path, cargo_lock: Path, build_lock: Path) -> dict:
    if root.is_symlink() or not root.is_dir() or {p.name for p in root.iterdir()} != {"cargo-crates", "python-wheels"}:
        raise AssertionError("invalid dependency closure root")
    digest, count = inventory(root, "dependency closure")
    crates = sorted((root / "cargo-crates").glob("*.crate"))
    wheels = sorted((root / "python-wheels").glob("*.whl"))
    if len(crates) != 23 or len(wheels) != 1 or count != 24:
        raise AssertionError("unexpected dependency closure counts")
    assert_regular(cargo_lock, "Cargo.lock")
    assert_regular(build_lock, "requirements-native-build.lock")
    return {"cargo_lock_sha256": sha256_file(cargo_lock), "native_build_lock_sha256": sha256_file(build_lock), "closure_sha256": digest, "file_count": count, "crate_count": 23, "python_wheel_count": 1}


def actual_vendor(root: Path) -> dict:
    digest, count = inventory(root, "vendor closure")
    packages = [p for p in root.iterdir() if p.is_dir() and not p.is_symlink()]
    if len(packages) != 23:
        raise AssertionError("unexpected vendor package count")
    return {"closure_sha256": digest, "file_count": count, "package_count": 23}


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


def attestation_message(payload: bytes) -> bytes:
    return DOMAIN + len(payload).to_bytes(8, "big") + payload


def verify(wheel_path: Path, rust_archive: Path, toolchain_path: Path, dep_root: Path, vendor_root: Path, cargo_lock: Path, build_lock: Path, source_sha: str, materials: Path, envelope: Path) -> None:
    rfc8032_selftest()
    raw, value = load_canonical(materials, "materials")
    _, env = load_canonical(envelope, "envelope")
    if frozenset(env) != ENVELOPE_KEYS:
        raise AssertionError("unexpected envelope fields")
    if env["schema"] != ENVELOPE_SCHEMA or env["algorithm"] != ALGORITHM or env["key_id"] != KEY_ID or env["payload_type"] != PAYLOAD_TYPE:
        raise AssertionError("unexpected envelope policy")
    if env["payload_sha256"] != hashlib.sha256(raw).hexdigest():
        raise AssertionError("payload SHA-256 mismatch")
    ed25519_verify(PINNED_PUBLIC_KEY, decode_signature(env["signature"]), attestation_message(raw))

    if frozenset(value) != MATERIAL_KEYS or value["schema"] != SCHEMA:
        raise AssertionError("unexpected material fields/schema")
    if not lower_hex(source_sha, 40):
        raise AssertionError("invalid source SHA")
    source = value["source"]
    if not isinstance(source, dict) or frozenset(source) != SOURCE_KEYS or source != {"repository": REPOSITORY, "commit": source_sha}:
        raise AssertionError("source identity mismatch")
    expected_builder = {"image": MANYLINUX_IMAGE, "python": "3.13.13", "rust": "1.98.0", "cargo": "1.98.0", "maturin": "1.15.0", "pyo3": "0.29.2"}
    builder = value["builder"]
    if not isinstance(builder, dict) or frozenset(builder) != BUILDER_KEYS or builder != expected_builder:
        raise AssertionError("builder identity mismatch")
    wheel = actual_wheel(wheel_path)
    artifact = value["artifact"]
    if not isinstance(artifact, dict) or frozenset(artifact) != ARTIFACT_KEYS or artifact != wheel:
        raise AssertionError("artifact identity mismatch")

    assert_regular(rust_archive, "Rust archive")
    toolchain = toolchain_manifest(toolchain_path)
    expected_rust = {"distribution_url": RUST_URL, "distribution_filename": RUST_ARCHIVE_NAME, "distribution_sha256": RUST_SHA256, "toolchain_manifest_sha256": toolchain[0], "toolchain_manifest_bytes": toolchain[1], "toolchain_file_count": toolchain[2]}
    rust = value["rust"]
    if not isinstance(rust, dict) or frozenset(rust) != RUST_KEYS or rust_archive.name != RUST_ARCHIVE_NAME or sha256_file(rust_archive) != RUST_SHA256 or rust != expected_rust:
        raise AssertionError("Rust distribution/toolchain identity mismatch")

    deps = actual_dependencies(dep_root, cargo_lock, build_lock)
    dep = value["dependencies"]
    if not isinstance(dep, dict) or frozenset(dep) != DEPENDENCY_KEYS or dep != deps:
        raise AssertionError("dependency identity mismatch")
    vend = actual_vendor(vendor_root)
    vendor = value["vendor"]
    if not isinstance(vendor, dict) or frozenset(vendor) != VENDOR_KEYS or vendor != vend:
        raise AssertionError("vendor identity mismatch")
    if value["production_consensus"] != "python-authoritative":
        raise AssertionError("unexpected production consensus claim")
    print(f"RUST-028 stdlib-only material consumer: GREEN source={source_sha} wheel={wheel['sha256']}")


def expect_failure(label: str, fn) -> None:
    try:
        fn()
    except (AssertionError, ValueError, json.JSONDecodeError):
        print(f"[GREEN] rejected {label}")
        return
    raise AssertionError(f"mutation unexpectedly accepted: {label}")


def selftest(wheel_path: Path, rust_archive: Path, toolchain_path: Path, dep_root: Path, vendor_root: Path, cargo_lock: Path, build_lock: Path, source_sha: str, materials: Path, envelope: Path) -> None:
    verify(wheel_path, rust_archive, toolchain_path, dep_root, vendor_root, cargo_lock, build_lock, source_sha, materials, envelope)
    _, base = load_canonical(materials, "materials")
    _, base_env = load_canonical(envelope, "envelope")
    cases = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        expect_failure("source SHA substitution", lambda: verify(wheel_path, rust_archive, toolchain_path, dep_root, vendor_root, cargo_lock, build_lock, "0" * 40, materials, envelope)); cases += 1

        bad_env = dict(base_env)
        sig = bytearray(decode_signature(bad_env["signature"])); sig[0] ^= 1
        bad_env["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        bad_env_path = root / "bad-envelope.json"; bad_env_path.write_bytes(canonical(bad_env))
        expect_failure("signature mutation", lambda: verify(wheel_path, rust_archive, toolchain_path, dep_root, vendor_root, cargo_lock, build_lock, source_sha, materials, bad_env_path)); cases += 1

        pretty = root / "materials.json"; pretty.write_text(json.dumps(base, indent=2) + "\n", encoding="utf-8")
        expect_failure("non-canonical materials", lambda: verify(wheel_path, rust_archive, toolchain_path, dep_root, vendor_root, cargo_lock, build_lock, source_sha, pretty, envelope)); cases += 1

        bad_wheel = root / WHEEL_FILENAME; payload = bytearray(wheel_path.read_bytes()); payload[len(payload)//2] ^= 1; bad_wheel.write_bytes(payload)
        expect_failure("wheel byte mutation", lambda: verify(bad_wheel, rust_archive, toolchain_path, dep_root, vendor_root, cargo_lock, build_lock, source_sha, materials, envelope)); cases += 1

        rust_dir = root / "rust"; rust_dir.mkdir(); bad_rust = rust_dir / RUST_ARCHIVE_NAME; bad_rust.write_bytes(b"substitute")
        expect_failure("Rust archive substitution", lambda: verify(wheel_path, bad_rust, toolchain_path, dep_root, vendor_root, cargo_lock, build_lock, source_sha, materials, envelope)); cases += 1

        bad_toolchain = root / "toolchain.json"; bad_toolchain.write_bytes(canonical({"schema": TOOLCHAIN_SCHEMA, "toolchain": TOOLCHAIN_NAME, "file_count": 1, "total_bytes": 1, "files": []}))
        expect_failure("toolchain manifest substitution", lambda: verify(wheel_path, rust_archive, bad_toolchain, dep_root, vendor_root, cargo_lock, build_lock, source_sha, materials, envelope)); cases += 1

        fake_dep = root / "dependencies"; (fake_dep / "cargo-crates").mkdir(parents=True); (fake_dep / "python-wheels").mkdir()
        expect_failure("dependency closure substitution", lambda: verify(wheel_path, rust_archive, toolchain_path, fake_dep, vendor_root, cargo_lock, build_lock, source_sha, materials, envelope)); cases += 1

        fake_vendor = root / "vendor"; (fake_vendor / "only-one-package").mkdir(parents=True); (fake_vendor / "only-one-package" / "x").write_bytes(b"x")
        expect_failure("vendor closure substitution", lambda: verify(wheel_path, rust_archive, toolchain_path, dep_root, fake_vendor, cargo_lock, build_lock, source_sha, materials, envelope)); cases += 1

        bad_cargo = root / "Cargo.lock"; shutil.copyfile(cargo_lock, bad_cargo); bad_cargo.write_bytes(bad_cargo.read_bytes() + b"\n# mutation\n")
        expect_failure("Cargo.lock mutation", lambda: verify(wheel_path, rust_archive, toolchain_path, dep_root, vendor_root, bad_cargo, build_lock, source_sha, materials, envelope)); cases += 1

        bad_build = root / "requirements-native-build.lock"; shutil.copyfile(build_lock, bad_build); bad_build.write_bytes(bad_build.read_bytes() + b"\n# mutation\n")
        expect_failure("native-build lock mutation", lambda: verify(wheel_path, rust_archive, toolchain_path, dep_root, vendor_root, cargo_lock, bad_build, source_sha, materials, envelope)); cases += 1

    assert cases == 10
    print("RUST-028 stdlib-only material consumer mutation contract: 10/10 expected cases passed")


def main() -> None:
    if len(sys.argv) != 12 or sys.argv[1] not in {"verify", "selftest"}:
        raise SystemExit("usage: rust_028_stdlib_material_verify.py verify|selftest WHEEL RUST TOOLCHAIN DEPS VENDOR CARGO_LOCK BUILD_LOCK SOURCE_SHA MATERIALS ENVELOPE")
    args = (Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), Path(sys.argv[6]), Path(sys.argv[7]), Path(sys.argv[8]), sys.argv[9], Path(sys.argv[10]), Path(sys.argv[11]))
    (verify if sys.argv[1] == "verify" else selftest)(*args)


if __name__ == "__main__":
    main()
