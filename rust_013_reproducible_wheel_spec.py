#!/usr/bin/env python3
"""RUST-013: verify two portable wheel builds are byte-for-byte reproducible."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path, PurePosixPath
import sys
import zipfile

EXPECTED_WHEEL = "axven_native-0.1.0-cp313-abi3-manylinux_2_28_x86_64.whl"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def single_wheel(directory: Path) -> Path:
    if directory.is_symlink() or not directory.is_dir():
        raise AssertionError(f"wheelhouse must be a real directory: {directory}")
    wheels = sorted(directory.glob("*.whl"))
    if len(wheels) != 1:
        raise AssertionError(f"expected one wheel in {directory}, got {wheels!r}")
    wheel = wheels[0]
    if wheel.is_symlink() or not wheel.is_file():
        raise AssertionError(f"wheel must be a real file: {wheel}")
    if wheel.name != EXPECTED_WHEEL:
        raise AssertionError(f"unexpected wheel name: {wheel.name}")
    if wheel.stat().st_size <= 0:
        raise AssertionError("empty wheel")
    return wheel


def first_byte_difference(left: bytes, right: bytes) -> int | None:
    for index, (a, b) in enumerate(zip(left, right)):
        if a != b:
            return index
    if len(left) != len(right):
        return min(len(left), len(right))
    return None


def expected_zip_time(epoch: int) -> tuple[int, int, int, int, int, int]:
    stamp = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return (stamp.year, stamp.month, stamp.day, stamp.hour, stamp.minute, stamp.second - stamp.second % 2)


def member_policy(info: zipfile.ZipInfo) -> None:
    name = info.filename
    if not name or name.startswith("/") or "\\" in name:
        raise AssertionError(f"unsafe wheel member: {name!r}")
    parts = PurePosixPath(name).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise AssertionError(f"unsafe wheel member path: {name!r}")


def info_fingerprint(info: zipfile.ZipInfo) -> tuple[object, ...]:
    return (
        info.filename,
        info.date_time,
        info.compress_type,
        info.CRC,
        info.file_size,
        info.compress_size,
        info.external_attr,
        info.create_system,
        info.flag_bits,
    )


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: rust_013_reproducible_wheel_spec.py WHEELHOUSE_A WHEELHOUSE_B SOURCE_DATE_EPOCH")

    left = single_wheel(Path(sys.argv[1]))
    right = single_wheel(Path(sys.argv[2]))
    try:
        epoch = int(sys.argv[3])
    except ValueError as exc:
        raise AssertionError("SOURCE_DATE_EPOCH must be an integer") from exc
    if epoch < 315532800:
        raise AssertionError(f"SOURCE_DATE_EPOCH predates ZIP-safe policy floor: {epoch}")

    checks = 0
    left_hash = sha256(left)
    right_hash = sha256(right)
    if left_hash != right_hash or left.stat().st_size != right.stat().st_size:
        raise AssertionError(
            f"wheel identity mismatch: A={left_hash}/{left.stat().st_size} B={right_hash}/{right.stat().st_size}"
        )
    checks += 1
    print(f"[GREEN] wheel SHA-256 and length match: {left_hash} :: {left.stat().st_size} bytes")

    left_bytes = left.read_bytes()
    right_bytes = right.read_bytes()
    if left_bytes != right_bytes:
        offset = first_byte_difference(left_bytes, right_bytes)
        raise AssertionError(f"wheel archives are not byte-identical; first difference at offset {offset}")
    checks += 1
    print("[GREEN] complete wheel archives are byte-for-byte identical")

    expected_time = expected_zip_time(epoch)
    with zipfile.ZipFile(left) as za, zipfile.ZipFile(right) as zb:
        if za.testzip() is not None or zb.testzip() is not None:
            raise AssertionError("wheel ZIP integrity check failed")
        infos_a = za.infolist()
        infos_b = zb.infolist()
        names_a = [item.filename for item in infos_a]
        names_b = [item.filename for item in infos_b]
        if len(names_a) != len(set(names_a)) or len(names_b) != len(set(names_b)):
            raise AssertionError("duplicate wheel member")
        if names_a != names_b:
            raise AssertionError(f"wheel member order mismatch: {names_a!r} != {names_b!r}")
        for info_a, info_b in zip(infos_a, infos_b):
            member_policy(info_a)
            member_policy(info_b)
            if info_fingerprint(info_a) != info_fingerprint(info_b):
                raise AssertionError(f"ZIP metadata mismatch for {info_a.filename}")
            if info_a.date_time != expected_time:
                raise AssertionError(
                    f"non-reproducible ZIP timestamp for {info_a.filename}: {info_a.date_time} != {expected_time}"
                )
        checks += 1
        print(f"[GREEN] ZIP member order/metadata are identical and epoch-pinned: {expected_time!r}")

        native_members = [name for name in names_a if name.endswith(".so")]
        record_members = [name for name in names_a if name.endswith(".dist-info/RECORD")]
        wheel_members = [name for name in names_a if name.endswith(".dist-info/WHEEL")]
        metadata_members = [name for name in names_a if name.endswith(".dist-info/METADATA")]
        if len(native_members) != 1 or len(record_members) != 1 or len(wheel_members) != 1 or len(metadata_members) != 1:
            raise AssertionError(
                ("unexpected wheel structure", native_members, record_members, wheel_members, metadata_members)
            )
        for name in names_a:
            payload_a = za.read(name)
            payload_b = zb.read(name)
            if payload_a != payload_b:
                raise AssertionError(f"member payload mismatch: {name}")
        checks += 1
        print("[GREEN] every wheel member payload is identical, including native binary and dist-info records")

    if left.resolve() == right.resolve():
        raise AssertionError("build A and build B resolved to the same wheel path")
    checks += 1
    print("[GREEN] reproducibility comparison uses distinct wheel paths")

    assert checks == 5
    print(f"RUST-013 reproducible portable wheel contract: 5/5 GREEN sha256={left_hash}")


if __name__ == "__main__":
    main()
