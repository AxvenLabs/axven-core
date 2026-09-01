#!/usr/bin/env python3
"""RUST-019: offline verifier for native build dependency archives."""
from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import tomllib
import zipfile

CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
EXPECTED_REQUIREMENT = "maturin==1.15.0"
HEX = frozenset("0123456789abcdef")
HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})(?:\s|$)")


def _lower_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(ch in HEX for ch in value)


def _regular_file(path: Path, label: str) -> None:
    if path.is_symlink():
        raise AssertionError(f"{label} must not be a symlink")
    if not path.is_file():
        raise AssertionError(f"{label} must be a regular file")


def _regular_dir(path: Path, label: str) -> None:
    if path.is_symlink():
        raise AssertionError(f"{label} must not be a symlink")
    if not path.is_dir():
        raise AssertionError(f"{label} must be a directory")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_component(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AssertionError(f"invalid {label}")
    if value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
        raise AssertionError(f"unsafe {label}: {value!r}")
    return value


def _cargo_packages(lock_path: Path) -> dict[str, str]:
    _regular_file(lock_path, "Cargo.lock")
    raw = lock_path.read_bytes()
    loaded = tomllib.loads(raw.decode("utf-8"))
    if loaded.get("version") != 4:
        raise AssertionError("Cargo.lock version must remain 4")
    packages = loaded.get("package")
    if not isinstance(packages, list) or not packages:
        raise AssertionError("Cargo.lock package list missing")

    expected: dict[str, str] = {}
    identities: set[tuple[str, str]] = set()
    for package in packages:
        if not isinstance(package, dict):
            raise AssertionError("invalid Cargo.lock package entry")
        source = package.get("source")
        if source is None:
            continue
        if source != CRATES_IO_SOURCE:
            raise AssertionError(f"unexpected Cargo package source: {source!r}")
        name = _safe_component(package.get("name"), "crate name")
        version = _safe_component(package.get("version"), "crate version")
        identity = (name, version)
        if identity in identities:
            raise AssertionError(f"duplicate registry package identity: {name} {version}")
        identities.add(identity)
        checksum = package.get("checksum")
        if not _lower_hex(checksum, 64):
            raise AssertionError(f"invalid checksum for {name} {version}")
        filename = f"{name}-{version}.crate"
        if filename in expected:
            raise AssertionError(f"crate archive filename collision: {filename}")
        expected[filename] = checksum
    if not expected:
        raise AssertionError("Cargo.lock has no registry dependency closure")
    return expected


def _python_hashes(lock_path: Path) -> frozenset[str]:
    _regular_file(lock_path, "requirements-native-build.lock")
    text = lock_path.read_text(encoding="utf-8")
    logical = " ".join(
        line.strip().rstrip("\\").strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    tokens = logical.split()
    requirements = [token for token in tokens if not token.startswith("--hash=")]
    if requirements != [EXPECTED_REQUIREMENT]:
        raise AssertionError(f"unexpected native build requirement contract: {requirements!r}")
    hashes = HASH_RE.findall(logical + " ")
    if not hashes or len(hashes) != len(set(hashes)):
        raise AssertionError("missing or duplicate Maturin SHA-256 lock hashes")
    for digest in hashes:
        if not _lower_hex(digest, 64):
            raise AssertionError("invalid Maturin lock hash")
    return frozenset(hashes)


def _safe_archive_name(name: str, root: str, label: str) -> None:
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        raise AssertionError(f"unsafe {label} member: {name!r}")
    parts = PurePosixPath(name).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise AssertionError(f"unsafe {label} member path: {name!r}")
    if parts[0] != root:
        raise AssertionError(f"{label} member escapes canonical package root: {name!r}")


def _validate_crate_archive(path: Path) -> None:
    _regular_file(path, f"crate archive {path.name}")
    if not path.name.endswith(".crate"):
        raise AssertionError(f"unexpected crate extension: {path.name}")
    root = path.name[:-6]
    if not root:
        raise AssertionError("empty crate archive root")
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            if not members:
                raise AssertionError(f"empty crate archive: {path.name}")
            seen: set[str] = set()
            for member in members:
                _safe_archive_name(member.name, root, "crate")
                if member.name in seen:
                    raise AssertionError(f"duplicate crate member: {member.name}")
                seen.add(member.name)
                if member.issym() or member.islnk() or member.ischr() or member.isblk() or member.isfifo():
                    raise AssertionError(f"unsafe crate member type: {member.name}")
                if not (member.isfile() or member.isdir()):
                    raise AssertionError(f"unsupported crate member type: {member.name}")
    except (tarfile.TarError, OSError) as exc:
        raise AssertionError(f"invalid crate archive: {path.name}") from exc


def _wheel_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _validate_wheel(path: Path) -> None:
    _regular_file(path, "Maturin wheel")
    if not path.name.startswith("maturin-1.15.0-") or not path.name.endswith(".whl"):
        raise AssertionError(f"unexpected Maturin wheel filename: {path.name}")
    try:
        with zipfile.ZipFile(path) as archive:
            if archive.testzip() is not None:
                raise AssertionError("Maturin wheel ZIP integrity failure")
            infos = archive.infolist()
            if not infos:
                raise AssertionError("empty Maturin wheel")
            seen: set[str] = set()
            for info in infos:
                name = info.filename
                if not name or name.startswith("/") or "\\" in name or "\x00" in name:
                    raise AssertionError(f"unsafe wheel member: {name!r}")
                parts = PurePosixPath(name).parts
                if any(part in {"", ".", ".."} for part in parts):
                    raise AssertionError(f"unsafe wheel member path: {name!r}")
                if name in seen:
                    raise AssertionError(f"duplicate wheel member: {name}")
                seen.add(name)
                if _wheel_is_symlink(info):
                    raise AssertionError(f"wheel symlink member rejected: {name}")
    except (zipfile.BadZipFile, OSError) as exc:
        raise AssertionError("invalid Maturin wheel") from exc


def collect_crates(lock_path: Path, cargo_home: Path, output: Path) -> None:
    expected = _cargo_packages(lock_path)
    _regular_dir(cargo_home, "Cargo home")
    if output.exists():
        if output.is_symlink() or not output.is_dir():
            raise AssertionError("crate output must be a normal directory")
        shutil.rmtree(output)
    output.mkdir(parents=True)

    candidates: dict[str, list[Path]] = {}
    cache = cargo_home / "registry" / "cache"
    _regular_dir(cache, "Cargo registry cache")
    for path in cache.rglob("*.crate"):
        if path.is_symlink() or not path.is_file():
            continue
        candidates.setdefault(path.name, []).append(path)

    for filename, digest in sorted(expected.items()):
        matches = [path for path in candidates.get(filename, []) if _sha256_file(path) == digest]
        if not matches:
            raise AssertionError(f"Cargo cache lacks checksum-valid archive: {filename}")
        destination = output / filename
        shutil.copyfile(matches[0], destination)
        if _sha256_file(destination) != digest:
            raise AssertionError(f"crate copy digest mismatch: {filename}")
    verify_crates(lock_path, output)
    print(f"RUST-019 collected Cargo dependency closure: {len(expected)} archives")


def verify_crates(lock_path: Path, crate_dir: Path) -> None:
    expected = _cargo_packages(lock_path)
    _regular_dir(crate_dir, "crate closure directory")
    entries = list(crate_dir.iterdir())
    if any(entry.is_symlink() or not entry.is_file() for entry in entries):
        raise AssertionError("crate closure must contain regular files only")
    actual_names = {entry.name for entry in entries}
    if actual_names != set(expected):
        missing = sorted(set(expected) - actual_names)
        extra = sorted(actual_names - set(expected))
        raise AssertionError(f"crate closure mismatch missing={missing} extra={extra}")
    if len(entries) != len(actual_names):
        raise AssertionError("duplicate crate directory entries")
    for filename, digest in sorted(expected.items()):
        path = crate_dir / filename
        if _sha256_file(path) != digest:
            raise AssertionError(f"crate SHA-256 mismatch: {filename}")
        _validate_crate_archive(path)


def verify_python(lock_path: Path, wheel_dir: Path) -> None:
    allowed_hashes = _python_hashes(lock_path)
    _regular_dir(wheel_dir, "Python wheel closure directory")
    entries = list(wheel_dir.iterdir())
    if len(entries) != 1:
        raise AssertionError("Python build-tool closure must contain exactly one wheel")
    wheel = entries[0]
    _regular_file(wheel, "Maturin wheel")
    if _sha256_file(wheel) not in allowed_hashes:
        raise AssertionError("Maturin wheel SHA-256 is not authorized by requirements lock")
    _validate_wheel(wheel)


def verify(cargo_lock: Path, requirements_lock: Path, crate_dir: Path, wheel_dir: Path) -> None:
    verify_crates(cargo_lock, crate_dir)
    verify_python(requirements_lock, wheel_dir)
    print(
        "RUST-019 offline dependency archive closure: GREEN "
        f"crates={len(_cargo_packages(cargo_lock))} python_wheels=1"
    )


def _must_reject(
    cargo_lock: Path,
    requirements_lock: Path,
    crate_dir: Path,
    wheel_dir: Path,
    label: str,
) -> None:
    try:
        verify(cargo_lock, requirements_lock, crate_dir, wheel_dir)
    except (AssertionError, UnicodeDecodeError, tomllib.TOMLDecodeError, zipfile.BadZipFile, tarfile.TarError):
        print(f"[GREEN] rejected {label}")
        return
    raise AssertionError(f"dependency closure mutation unexpectedly accepted: {label}")


def _copy_tree(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, symlinks=True)


def selftest(cargo_lock: Path, requirements_lock: Path, crate_dir: Path, wheel_dir: Path) -> None:
    verify(cargo_lock, requirements_lock, crate_dir, wheel_dir)
    crate_names = sorted(_cargo_packages(cargo_lock))
    target = crate_names[0]
    checks = 0

    with tempfile.TemporaryDirectory(prefix="axven-rust019-") as temp:
        root = Path(temp)

        crates = root / "crate-byte"
        _copy_tree(crate_dir, crates)
        path = crates / target
        path.write_bytes(path.read_bytes() + b"\x00")
        _must_reject(cargo_lock, requirements_lock, crates, wheel_dir, "crate byte mutation")
        checks += 1

        crates = root / "crate-missing"
        _copy_tree(crate_dir, crates)
        (crates / target).unlink()
        _must_reject(cargo_lock, requirements_lock, crates, wheel_dir, "missing crate archive")
        checks += 1

        crates = root / "crate-extra"
        _copy_tree(crate_dir, crates)
        (crates / "unexpected-0.0.0.crate").write_bytes(b"unexpected")
        _must_reject(cargo_lock, requirements_lock, crates, wheel_dir, "extra crate archive")
        checks += 1

        crates = root / "crate-symlink"
        _copy_tree(crate_dir, crates)
        original = crates / target
        backup = crates / (target + ".real")
        original.rename(backup)
        original.symlink_to(backup.name)
        backup.unlink()
        _must_reject(cargo_lock, requirements_lock, crates, wheel_dir, "crate symlink substitution")
        checks += 1

        mutated_lock = root / "Cargo.lock"
        text = cargo_lock.read_text(encoding="utf-8")
        match = re.search(r'checksum = "([0-9a-f]{64})"', text)
        if match is None:
            raise AssertionError("selftest could not locate Cargo checksum")
        replacement = "0" * 64 if match.group(1) != "0" * 64 else "1" * 64
        mutated_lock.write_text(text[: match.start(1)] + replacement + text[match.end(1) :], encoding="utf-8")
        _must_reject(mutated_lock, requirements_lock, crate_dir, wheel_dir, "Cargo.lock checksum substitution")
        checks += 1

        wheels = root / "wheel-byte"
        _copy_tree(wheel_dir, wheels)
        wheel = next(wheels.iterdir())
        wheel.write_bytes(wheel.read_bytes() + b"\x00")
        _must_reject(cargo_lock, requirements_lock, crate_dir, wheels, "Maturin wheel byte mutation")
        checks += 1

        wheels = root / "wheel-extra"
        _copy_tree(wheel_dir, wheels)
        (wheels / "extra.whl").write_bytes(b"extra")
        _must_reject(cargo_lock, requirements_lock, crate_dir, wheels, "extra Python wheel")
        checks += 1

        req = root / "requirements-native-build.lock"
        req.write_text("maturin==1.14.0 --hash=sha256:" + "0" * 64 + "\n", encoding="utf-8")
        _must_reject(cargo_lock, req, crate_dir, wheel_dir, "native build requirement substitution")
        checks += 1

    if checks != 8:
        raise AssertionError(checks)
    verify(cargo_lock, requirements_lock, crate_dir, wheel_dir)
    print("RUST-019 offline dependency closure fail-closed contract: 8/8 GREEN")


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("missing command")
    command = sys.argv[1]
    if command == "collect-crates" and len(sys.argv) == 5:
        collect_crates(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]))
        return
    if command in {"verify", "selftest"} and len(sys.argv) == 6:
        args = tuple(Path(value) for value in sys.argv[2:])
        if command == "verify":
            verify(*args)
        else:
            selftest(*args)
        return
    raise SystemExit(
        "usage:\n"
        "  rust_019_offline_dependency_closure.py collect-crates CARGO_LOCK CARGO_HOME OUT_DIR\n"
        "  rust_019_offline_dependency_closure.py {verify|selftest} CARGO_LOCK REQUIREMENTS_LOCK CRATE_DIR WHEEL_DIR"
    )


if __name__ == "__main__":
    main()
