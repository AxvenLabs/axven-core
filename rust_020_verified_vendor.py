#!/usr/bin/env python3
"""RUST-020: build and verify a Cargo directory source from RUST-019 archives."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile
import tempfile

import rust_019_offline_dependency_closure as dependency

CHECKSUM_FILENAME = ".cargo-checksum.json"
VENDOR_CONTAINER_PATH = "/vendor"
CONFIG_TEXT = """[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = \"/vendor\"\n\n[net]\noffline = true\n"""
HEX = frozenset("0123456789abcdef")


def _canonical_json(obj: object) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _lower_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(ch in HEX for ch in value)


def _regular_dir(path: Path, label: str) -> None:
    if path.is_symlink():
        raise AssertionError(f"{label} must not be a symlink")
    if not path.is_dir():
        raise AssertionError(f"{label} must be a directory")


def _regular_file(path: Path, label: str) -> None:
    if path.is_symlink():
        raise AssertionError(f"{label} must not be a symlink")
    if not path.is_file():
        raise AssertionError(f"{label} must be a regular file")


def _package_name_from_archive(filename: str) -> str:
    if not filename.endswith(".crate") or len(filename) <= len(".crate"):
        raise AssertionError(f"unexpected crate archive filename: {filename!r}")
    return filename[: -len(".crate")]


def _relative_member(member_name: str, package_root: str) -> PurePosixPath | None:
    dependency._safe_archive_name(member_name, package_root, "crate")
    parts = PurePosixPath(member_name).parts
    if parts == (package_root,):
        return None
    relative = PurePosixPath(*parts[1:])
    if relative.as_posix() == CHECKSUM_FILENAME:
        raise AssertionError("crate archive must not supply Cargo vendor checksum metadata")
    return relative


def _safe_destination(package_dir: Path, relative: PurePosixPath) -> Path:
    destination = package_dir.joinpath(*relative.parts)
    resolved_parent = destination.parent.resolve()
    root = package_dir.resolve()
    if resolved_parent != root and root not in resolved_parent.parents:
        raise AssertionError(f"vendor destination escaped package root: {relative.as_posix()}")
    return destination


def _extract_one(archive_path: Path, package_dir: Path, package_root: str) -> None:
    dependency._validate_crate_archive(archive_path)
    seen: set[str] = set()
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in archive.getmembers():
            relative = _relative_member(member.name, package_root)
            if relative is None:
                continue
            relative_text = relative.as_posix()
            if relative_text in seen:
                raise AssertionError(f"duplicate vendor member: {relative_text}")
            seen.add(relative_text)
            destination = _safe_destination(package_dir, relative)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise AssertionError(f"unsupported crate member type: {member.name}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            extracted = archive.extractfile(member)
            if extracted is None:
                raise AssertionError(f"could not read crate member: {member.name}")
            data = extracted.read()
            destination.write_bytes(data)
    if not seen:
        raise AssertionError(f"crate archive produced no vendorable members: {archive_path.name}")


def _package_files(package_dir: Path) -> dict[str, str]:
    _regular_dir(package_dir, f"vendor package {package_dir.name}")
    files: dict[str, str] = {}
    for path in sorted(package_dir.rglob("*"), key=lambda value: value.as_posix()):
        if path.is_symlink():
            raise AssertionError(f"vendor symlink rejected: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise AssertionError(f"unsupported vendor filesystem entry: {path}")
        relative = path.relative_to(package_dir).as_posix()
        if relative == CHECKSUM_FILENAME:
            continue
        if not relative or relative.startswith("/") or "\\" in relative:
            raise AssertionError(f"unsafe vendor relative path: {relative!r}")
        parts = PurePosixPath(relative).parts
        if any(part in {"", ".", ".."} for part in parts):
            raise AssertionError(f"unsafe vendor relative path: {relative!r}")
        files[relative] = _sha256_file(path)
    if not files:
        raise AssertionError(f"vendor package has no regular source files: {package_dir.name}")
    return files


def _write_checksum(package_dir: Path, package_checksum: str) -> None:
    if not _lower_hex(package_checksum, 64):
        raise AssertionError("invalid package checksum")
    payload = {"files": _package_files(package_dir), "package": package_checksum}
    (package_dir / CHECKSUM_FILENAME).write_bytes(_canonical_json(payload))


def build_vendor(cargo_lock: Path, crate_dir: Path, vendor_dir: Path) -> None:
    expected = dependency._cargo_packages(cargo_lock)
    dependency.verify_crates(cargo_lock, crate_dir)
    if vendor_dir.exists():
        if vendor_dir.is_symlink() or not vendor_dir.is_dir():
            raise AssertionError("vendor destination must be a normal directory")
        shutil.rmtree(vendor_dir)
    vendor_dir.mkdir(parents=True)

    for archive_name, package_checksum in sorted(expected.items()):
        package_root = _package_name_from_archive(archive_name)
        package_dir = vendor_dir / package_root
        package_dir.mkdir()
        _extract_one(crate_dir / archive_name, package_dir, package_root)
        _write_checksum(package_dir, package_checksum)

    verify_vendor(cargo_lock, vendor_dir)
    print(f"RUST-020 built verified Cargo vendor closure: packages={len(expected)}")


def _load_checksum(path: Path) -> dict:
    _regular_file(path, "Cargo vendor checksum metadata")
    raw = path.read_bytes()
    loaded = json.loads(raw.decode("utf-8"))
    if not isinstance(loaded, dict):
        raise AssertionError("Cargo vendor checksum metadata must be an object")
    if raw != _canonical_json(loaded):
        raise AssertionError("Cargo vendor checksum metadata must be canonical JSON")
    if frozenset(loaded) != frozenset({"files", "package"}):
        raise AssertionError("unexpected Cargo vendor checksum fields")
    if not isinstance(loaded["files"], dict) or not loaded["files"]:
        raise AssertionError("Cargo vendor checksum file map missing")
    if not _lower_hex(loaded["package"], 64):
        raise AssertionError("invalid Cargo vendor package checksum")
    for name, digest in loaded["files"].items():
        if not isinstance(name, str) or not name or name.startswith("/") or "\\" in name:
            raise AssertionError(f"invalid Cargo vendor checksum path: {name!r}")
        parts = PurePosixPath(name).parts
        if any(part in {"", ".", ".."} for part in parts):
            raise AssertionError(f"invalid Cargo vendor checksum path: {name!r}")
        if not _lower_hex(digest, 64):
            raise AssertionError(f"invalid Cargo vendor file digest: {name!r}")
    return loaded


def verify_vendor(cargo_lock: Path, vendor_dir: Path) -> None:
    expected_archives = dependency._cargo_packages(cargo_lock)
    expected_packages = {
        _package_name_from_archive(filename): digest for filename, digest in expected_archives.items()
    }
    if len(expected_packages) != len(expected_archives):
        raise AssertionError("vendor package directory identity collision")
    _regular_dir(vendor_dir, "Cargo vendor closure")
    entries = list(vendor_dir.iterdir())
    if any(entry.is_symlink() or not entry.is_dir() for entry in entries):
        raise AssertionError("Cargo vendor closure must contain package directories only")
    actual_names = {entry.name for entry in entries}
    if actual_names != set(expected_packages):
        missing = sorted(set(expected_packages) - actual_names)
        extra = sorted(actual_names - set(expected_packages))
        raise AssertionError(f"vendor package-set mismatch missing={missing} extra={extra}")

    for package_name, package_checksum in sorted(expected_packages.items()):
        package_dir = vendor_dir / package_name
        metadata = _load_checksum(package_dir / CHECKSUM_FILENAME)
        if metadata["package"] != package_checksum:
            raise AssertionError(f"vendor package checksum mismatch: {package_name}")
        actual_files = _package_files(package_dir)
        if set(metadata["files"]) != set(actual_files):
            missing = sorted(set(actual_files) - set(metadata["files"]))
            extra = sorted(set(metadata["files"]) - set(actual_files))
            raise AssertionError(
                f"vendor file-set mismatch package={package_name} missing_claims={missing} extra_claims={extra}"
            )
        for relative, digest in sorted(actual_files.items()):
            if metadata["files"][relative] != digest:
                raise AssertionError(f"vendor file digest mismatch: {package_name}/{relative}")


def write_config(cargo_home: Path) -> None:
    if cargo_home.exists():
        if cargo_home.is_symlink() or not cargo_home.is_dir():
            raise AssertionError("Cargo home destination must be a normal directory")
        if any(cargo_home.iterdir()):
            raise AssertionError("Cargo home must be empty before RUST-020 config creation")
    else:
        cargo_home.mkdir(parents=True)
    (cargo_home / "config.toml").write_text(CONFIG_TEXT, encoding="utf-8")
    entries = list(cargo_home.iterdir())
    if len(entries) != 1 or entries[0].name != "config.toml" or not entries[0].is_file():
        raise AssertionError("unexpected RUST-020 Cargo home contents")
    print(f"RUST-020 wrote offline Cargo source replacement: {VENDOR_CONTAINER_PATH}")


def verify(cargo_lock: Path, vendor_dir: Path) -> None:
    verify_vendor(cargo_lock, vendor_dir)
    print(f"RUST-020 verified Cargo vendor closure: packages={len(dependency._cargo_packages(cargo_lock))}")


def _copy_vendor(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, symlinks=True)


def _first_source_file(vendor_dir: Path) -> tuple[Path, Path]:
    for package_dir in sorted(vendor_dir.iterdir(), key=lambda value: value.name):
        if package_dir.is_dir() and not package_dir.is_symlink():
            for path in sorted(package_dir.rglob("*"), key=lambda value: value.as_posix()):
                if path.is_file() and not path.is_symlink() and path.name != CHECKSUM_FILENAME:
                    return package_dir, path
    raise AssertionError("selftest could not find a vendored source file")


def _must_reject(cargo_lock: Path, vendor_dir: Path, label: str) -> None:
    try:
        verify_vendor(cargo_lock, vendor_dir)
    except (AssertionError, UnicodeDecodeError, json.JSONDecodeError):
        print(f"[GREEN] rejected {label}")
        return
    raise AssertionError(f"vendor mutation unexpectedly accepted: {label}")


def _mutate_hex(value: str) -> str:
    if not _lower_hex(value, 64):
        raise AssertionError("selftest expected lowercase SHA-256")
    return ("0" if value[0] != "0" else "1") + value[1:]


def selftest(cargo_lock: Path, vendor_dir: Path) -> None:
    verify_vendor(cargo_lock, vendor_dir)
    packages = sorted(entry.name for entry in vendor_dir.iterdir())
    first_package = packages[0]
    checks = 0

    with tempfile.TemporaryDirectory(prefix="axven-rust020-") as temp:
        root = Path(temp)

        mutated = root / "file-byte"
        _copy_vendor(vendor_dir, mutated)
        package_dir, source_file = _first_source_file(mutated)
        source_file.write_bytes(source_file.read_bytes() + b"\x00")
        _must_reject(cargo_lock, mutated, "vendored source byte mutation")
        checks += 1

        mutated = root / "file-missing"
        _copy_vendor(vendor_dir, mutated)
        _, source_file = _first_source_file(mutated)
        source_file.unlink()
        _must_reject(cargo_lock, mutated, "missing vendored source file")
        checks += 1

        mutated = root / "file-extra"
        _copy_vendor(vendor_dir, mutated)
        package_dir = mutated / first_package
        (package_dir / "unexpected-rust020-file").write_bytes(b"unexpected")
        _must_reject(cargo_lock, mutated, "extra vendored source file")
        checks += 1

        mutated = root / "file-symlink"
        _copy_vendor(vendor_dir, mutated)
        _, source_file = _first_source_file(mutated)
        backup = source_file.with_name(source_file.name + ".rust020-real")
        source_file.rename(backup)
        source_file.symlink_to(backup.name)
        _must_reject(cargo_lock, mutated, "vendored source symlink substitution")
        checks += 1

        mutated = root / "checksum-file"
        _copy_vendor(vendor_dir, mutated)
        package_dir = mutated / first_package
        checksum_path = package_dir / CHECKSUM_FILENAME
        metadata = _load_checksum(checksum_path)
        key = sorted(metadata["files"])[0]
        metadata["files"][key] = _mutate_hex(metadata["files"][key])
        checksum_path.write_bytes(_canonical_json(metadata))
        _must_reject(cargo_lock, mutated, "Cargo vendor file-checksum substitution")
        checks += 1

        mutated = root / "checksum-package"
        _copy_vendor(vendor_dir, mutated)
        package_dir = mutated / first_package
        checksum_path = package_dir / CHECKSUM_FILENAME
        metadata = _load_checksum(checksum_path)
        metadata["package"] = _mutate_hex(metadata["package"])
        checksum_path.write_bytes(_canonical_json(metadata))
        _must_reject(cargo_lock, mutated, "Cargo vendor package-checksum substitution")
        checks += 1

        mutated = root / "package-extra"
        _copy_vendor(vendor_dir, mutated)
        (mutated / "unexpected-0.0.0").mkdir()
        _must_reject(cargo_lock, mutated, "extra vendor package directory")
        checks += 1

        mutated = root / "package-missing"
        _copy_vendor(vendor_dir, mutated)
        shutil.rmtree(mutated / first_package)
        _must_reject(cargo_lock, mutated, "missing vendor package directory")
        checks += 1

    if checks != 8:
        raise AssertionError(checks)
    verify_vendor(cargo_lock, vendor_dir)
    print("RUST-020 verified Cargo vendor fail-closed contract: 8/8 GREEN")


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("missing command")
    command = sys.argv[1]
    if command == "build" and len(sys.argv) == 5:
        build_vendor(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]))
        return
    if command in {"verify", "selftest"} and len(sys.argv) == 4:
        args = (Path(sys.argv[2]), Path(sys.argv[3]))
        if command == "verify":
            verify(*args)
        else:
            selftest(*args)
        return
    if command == "write-config" and len(sys.argv) == 3:
        write_config(Path(sys.argv[2]))
        return
    raise SystemExit(
        "usage:\n"
        "  rust_020_verified_vendor.py build CARGO_LOCK CRATE_DIR VENDOR_DIR\n"
        "  rust_020_verified_vendor.py {verify|selftest} CARGO_LOCK VENDOR_DIR\n"
        "  rust_020_verified_vendor.py write-config CARGO_HOME"
    )


if __name__ == "__main__":
    main()
