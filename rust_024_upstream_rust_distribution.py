#!/usr/bin/env python3
"""RUST-024: verify and safely extract the pinned upstream Rust distribution."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile

ARCHIVE_NAME = "rust-1.98.0-x86_64-unknown-linux-gnu.tar.xz"
ARCHIVE_ROOT = "rust-1.98.0-x86_64-unknown-linux-gnu"
UPSTREAM_URL = (
    "https://static.rust-lang.org/dist/2026-08-20/"
    "rust-1.98.0-x86_64-unknown-linux-gnu.tar.xz"
)
UPSTREAM_SHA256 = "ed8ee2df70909c88cbaf87a6cfa3920dac00b537de12a6abe6906641e0f5952f"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _regular_file(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise AssertionError(f"{label} must be a regular file")


def _member_parts(name: str) -> list[str]:
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        raise AssertionError(f"unsafe archive member path: {name!r}")
    trimmed = name[:-1] if name.endswith("/") else name
    parts = trimmed.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise AssertionError(f"non-canonical archive member path: {name!r}")
    if parts[0] != ARCHIVE_ROOT:
        raise AssertionError(f"archive member outside pinned root: {name!r}")
    return parts


def _normalize_link(base: list[str], linkname: str) -> list[str]:
    if not linkname or linkname.startswith("/") or "\\" in linkname or "\x00" in linkname:
        raise AssertionError(f"unsafe archive link target: {linkname!r}")
    stack = list(base)
    for part in linkname.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not stack:
                raise AssertionError(f"archive link escapes root: {linkname!r}")
            stack.pop()
            continue
        stack.append(part)
    if not stack or stack[0] != ARCHIVE_ROOT:
        raise AssertionError(f"archive link escapes pinned root: {linkname!r}")
    return stack


def _validate_members(members: list[tarfile.TarInfo]) -> None:
    if not members:
        raise AssertionError("empty Rust distribution archive")
    seen: set[str] = set()
    has_install = False
    for member in members:
        parts = _member_parts(member.name)
        canonical_name = "/".join(parts)
        if canonical_name in seen:
            raise AssertionError(f"duplicate archive member: {canonical_name}")
        seen.add(canonical_name)
        if member.ischr() or member.isblk() or member.isfifo():
            raise AssertionError(f"special archive member rejected: {member.name}")
        if member.issym():
            _normalize_link(parts[:-1], member.linkname)
        elif member.islnk():
            target_parts = member.linkname.rstrip("/").split("/")
            if target_parts and target_parts[0] == ARCHIVE_ROOT:
                _normalize_link([], member.linkname)
            else:
                _normalize_link(parts[:-1], member.linkname)
        elif not (member.isfile() or member.isdir()):
            raise AssertionError(f"unsupported archive member type: {member.name}")
        if canonical_name == f"{ARCHIVE_ROOT}/install.sh":
            if not member.isfile():
                raise AssertionError("install.sh must be a regular archive file")
            has_install = True
    if not has_install:
        raise AssertionError("Rust distribution install.sh missing")


def _validate_archive_structure(path: Path) -> int:
    try:
        with tarfile.open(path, mode="r:xz") as archive:
            members = archive.getmembers()
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise AssertionError("invalid Rust distribution tar.xz") from exc
    _validate_members(members)
    return len(members)


def verify_archive(path: Path) -> None:
    _regular_file(path, "Rust distribution archive")
    if path.name != ARCHIVE_NAME:
        raise AssertionError(f"unexpected Rust archive filename: {path.name!r}")
    digest = _sha256(path)
    if digest != UPSTREAM_SHA256:
        raise AssertionError(f"Rust distribution SHA-256 mismatch: {digest}")
    count = _validate_archive_structure(path)
    print(
        "RUST-024 upstream Rust distribution: GREEN "
        f"sha256={digest} members={count} url={UPSTREAM_URL}"
    )


def extract_archive(path: Path, destination: Path) -> Path:
    verify_archive(path)
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir():
            raise AssertionError("extraction destination must be a normal directory")
        if any(destination.iterdir()):
            raise AssertionError("extraction destination must be empty")
    else:
        destination.mkdir(parents=True)
    try:
        with tarfile.open(path, mode="r:xz") as archive:
            archive.extractall(destination, filter="data")
    except (tarfile.TarError, OSError, ValueError) as exc:
        raise AssertionError("safe Rust distribution extraction failed") from exc
    root = destination / ARCHIVE_ROOT
    if root.is_symlink() or not root.is_dir():
        raise AssertionError("extracted Rust distribution root missing")
    install = root / "install.sh"
    _regular_file(install, "extracted install.sh")
    print(f"RUST-024 safely extracted authenticated distribution: {root}")
    return root


def _tarinfo(name: str, kind: bytes = tarfile.REGTYPE, linkname: str = "") -> tarfile.TarInfo:
    item = tarfile.TarInfo(name)
    item.type = kind
    item.linkname = linkname
    item.size = 0
    return item


def _must_reject_members(members: list[tarfile.TarInfo], label: str) -> None:
    try:
        _validate_members(members)
    except AssertionError:
        print(f"[GREEN] rejected {label}")
        return
    raise AssertionError(f"unsafe Rust archive mutation unexpectedly accepted: {label}")


def selftest() -> None:
    install = _tarinfo(f"{ARCHIVE_ROOT}/install.sh")
    safe = [
        _tarinfo(ARCHIVE_ROOT, tarfile.DIRTYPE),
        install,
        _tarinfo(f"{ARCHIVE_ROOT}/bin", tarfile.DIRTYPE),
        _tarinfo(f"{ARCHIVE_ROOT}/bin/rustc"),
    ]
    _validate_members(safe)
    checks = 0

    _must_reject_members([install, _tarinfo("../escape")], "path traversal")
    checks += 1
    _must_reject_members([install, _tarinfo("/absolute")], "absolute member path")
    checks += 1
    _must_reject_members([install, _tarinfo("different-root/file")], "unexpected top-level root")
    checks += 1
    _must_reject_members(
        [install, _tarinfo(f"{ARCHIVE_ROOT}/bin/bad", tarfile.SYMTYPE, "../../../escape")],
        "escaping symbolic link",
    )
    checks += 1
    _must_reject_members(
        [install, _tarinfo(f"{ARCHIVE_ROOT}/bin/bad", tarfile.LNKTYPE, "../../../escape")],
        "escaping hard link",
    )
    checks += 1
    _must_reject_members(
        [install, _tarinfo(f"{ARCHIVE_ROOT}/device", tarfile.CHRTYPE)],
        "device entry",
    )
    checks += 1
    _must_reject_members([install, _tarinfo(f"{ARCHIVE_ROOT}/install.sh")], "duplicate member")
    checks += 1

    with tempfile.TemporaryDirectory(prefix="axven-rust024-") as temp:
        path = Path(temp) / ARCHIVE_NAME
        path.write_bytes(b"not-the-pinned-rust-distribution")
        try:
            verify_archive(path)
        except AssertionError:
            print("[GREEN] rejected archive digest substitution")
        else:
            raise AssertionError("archive digest substitution unexpectedly accepted")
    checks += 1

    if checks != 8:
        raise AssertionError(checks)
    print("RUST-024 upstream distribution fail-closed contract: 8/8 GREEN")


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("missing command")
    command = sys.argv[1]
    if command == "verify-archive" and len(sys.argv) == 3:
        verify_archive(Path(sys.argv[2]))
        return
    if command == "extract" and len(sys.argv) == 4:
        extract_archive(Path(sys.argv[2]), Path(sys.argv[3]))
        return
    if command == "selftest" and len(sys.argv) == 2:
        selftest()
        return
    raise SystemExit("usage: rust_024_upstream_rust_distribution.py verify-archive ARCHIVE | extract ARCHIVE DEST | selftest")


if __name__ == "__main__":
    main()
