#!/usr/bin/env python3
"""RUST-021: verify a wheel built from authenticated offline dependencies matches its reference."""
from __future__ import annotations

from pathlib import Path
import shutil
import sys
import tempfile

import rust_013_reproducible_wheel_spec as repro


def verify(reference_dir: Path, offline_dir: Path) -> None:
    reference = repro.single_wheel(reference_dir)
    offline = repro.single_wheel(offline_dir)
    if reference.resolve() == offline.resolve():
        raise AssertionError("reference and offline wheel paths must be distinct")

    reference_hash = repro.sha256(reference)
    offline_hash = repro.sha256(offline)
    reference_size = reference.stat().st_size
    offline_size = offline.stat().st_size
    if reference_hash != offline_hash or reference_size != offline_size:
        raise AssertionError(
            "RUST-021 wheel identity mismatch: "
            f"reference={reference_hash}/{reference_size} offline={offline_hash}/{offline_size}"
        )

    if reference.read_bytes() != offline.read_bytes():
        raise AssertionError("RUST-021 wheel archives are not byte-for-byte identical")

    print(
        "RUST-021 verified dependency-consumed wheel identity: GREEN "
        f"sha256={reference_hash} bytes={reference_size}"
    )


def _must_reject(reference_dir: Path, offline_dir: Path, label: str) -> None:
    try:
        verify(reference_dir, offline_dir)
    except AssertionError:
        print(f"[GREEN] rejected {label}")
        return
    raise AssertionError(f"RUST-021 mutation unexpectedly accepted: {label}")


def selftest(reference_dir: Path, offline_dir: Path) -> None:
    verify(reference_dir, offline_dir)
    source = repro.single_wheel(offline_dir)
    checks = 0

    with tempfile.TemporaryDirectory(prefix="axven-rust021-") as temp:
        root = Path(temp)

        mutated = root / "byte"
        shutil.copytree(offline_dir, mutated)
        wheel = repro.single_wheel(mutated)
        wheel.write_bytes(wheel.read_bytes() + b"\x00")
        _must_reject(reference_dir, mutated, "offline wheel byte mutation")
        checks += 1

        mutated = root / "missing"
        shutil.copytree(offline_dir, mutated)
        repro.single_wheel(mutated).unlink()
        _must_reject(reference_dir, mutated, "missing offline wheel")
        checks += 1

        mutated = root / "extra"
        shutil.copytree(offline_dir, mutated)
        (mutated / "unexpected.whl").write_bytes(b"unexpected")
        _must_reject(reference_dir, mutated, "extra offline wheel")
        checks += 1

        mutated = root / "rename"
        shutil.copytree(offline_dir, mutated)
        wheel = repro.single_wheel(mutated)
        wheel.rename(mutated / "renamed.whl")
        _must_reject(reference_dir, mutated, "offline wheel filename substitution")
        checks += 1

        mutated = root / "truncate"
        shutil.copytree(offline_dir, mutated)
        wheel = repro.single_wheel(mutated)
        payload = wheel.read_bytes()
        if len(payload) < 2:
            raise AssertionError("wheel too small for truncation selftest")
        wheel.write_bytes(payload[:-1])
        _must_reject(reference_dir, mutated, "offline wheel truncation")
        checks += 1

        fake_reference = root / "reference-byte"
        shutil.copytree(reference_dir, fake_reference)
        wheel = repro.single_wheel(fake_reference)
        wheel.write_bytes(wheel.read_bytes() + b"\x01")
        _must_reject(fake_reference, offline_dir, "reference wheel byte substitution")
        checks += 1

    if checks != 6:
        raise AssertionError(checks)
    verify(reference_dir, offline_dir)
    print("RUST-021 dependency-consumed rebuild fail-closed contract: 6/6 GREEN")


def main() -> None:
    if len(sys.argv) != 4 or sys.argv[1] not in {"verify", "selftest"}:
        raise SystemExit(
            "usage: rust_021_verified_dependency_rebuild_spec.py "
            "{verify|selftest} REFERENCE_WHEELHOUSE OFFLINE_WHEELHOUSE"
        )
    reference = Path(sys.argv[2])
    offline = Path(sys.argv[3])
    if sys.argv[1] == "verify":
        verify(reference, offline)
    else:
        selftest(reference, offline)


if __name__ == "__main__":
    main()
