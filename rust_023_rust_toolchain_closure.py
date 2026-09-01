#!/usr/bin/env python3
"""RUST-023: exact Rust toolchain filesystem closure verifier."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile

SCHEMA = "axven-rust-toolchain-closure-v1"
TOOLCHAIN = "1.98.0-x86_64-unknown-linux-gnu"
HEX = frozenset("0123456789abcdef")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _safe_rel(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise AssertionError("invalid toolchain path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or "\\" in value or "\x00" in value:
        raise AssertionError(f"unsafe toolchain path: {value!r}")
    parts = pure.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise AssertionError(f"unsafe toolchain path: {value!r}")
    canonical = pure.as_posix()
    if canonical != value:
        raise AssertionError(f"non-canonical toolchain path: {value!r}")
    return canonical


def _root(root: Path) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise AssertionError("toolchain root must be a real directory")
    if root.name != TOOLCHAIN:
        raise AssertionError(f"unexpected toolchain root: {root.name!r}")
    return root


def _metadata(root: Path) -> dict[str, tuple[int, int]]:
    root = _root(root)
    result: dict[str, tuple[int, int]] = {}
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in list(dirs):
            path = current_path / name
            if path.is_symlink():
                raise AssertionError(f"toolchain directory symlink rejected: {path.relative_to(root)}")
            if not path.is_dir():
                raise AssertionError(f"unsupported toolchain directory entry: {path.relative_to(root)}")
        for name in files:
            path = current_path / name
            rel = path.relative_to(root).as_posix()
            _safe_rel(rel)
            if path.is_symlink():
                raise AssertionError(f"toolchain file symlink rejected: {rel}")
            st = path.stat()
            if not stat.S_ISREG(st.st_mode):
                raise AssertionError(f"unsupported toolchain file type: {rel}")
            mode = stat.S_IMODE(st.st_mode)
            result[rel] = (st.st_size, mode)
    if not result:
        raise AssertionError("empty Rust toolchain closure")
    return result


def _manifest_entries(root: Path) -> list[dict[str, object]]:
    meta = _metadata(root)
    entries: list[dict[str, object]] = []
    for rel in sorted(meta):
        size, mode = meta[rel]
        digest = _sha256(root / rel)
        entries.append({"path": rel, "sha256": digest, "size": size, "mode": mode})
    return entries


def _validate_manifest_object(value: object) -> tuple[list[dict[str, object]], int, int]:
    if not isinstance(value, dict):
        raise AssertionError("manifest must be an object")
    if set(value) != {"schema", "toolchain", "file_count", "total_bytes", "files"}:
        raise AssertionError("unexpected manifest fields")
    if value["schema"] != SCHEMA:
        raise AssertionError("unexpected manifest schema")
    if value["toolchain"] != TOOLCHAIN:
        raise AssertionError("unexpected toolchain identity")
    files = value["files"]
    if not isinstance(files, list) or not files:
        raise AssertionError("manifest files missing")
    normalized: list[dict[str, object]] = []
    seen: set[str] = set()
    previous = ""
    total_bytes = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size", "mode"}:
            raise AssertionError("invalid manifest file entry")
        rel = _safe_rel(item["path"])
        if rel in seen:
            raise AssertionError(f"duplicate manifest path: {rel}")
        if previous and rel <= previous:
            raise AssertionError("manifest paths must be strictly sorted")
        seen.add(rel)
        previous = rel
        digest = item["sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(ch not in HEX for ch in digest):
            raise AssertionError(f"invalid SHA-256 for {rel}")
        size = item["size"]
        mode = item["mode"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise AssertionError(f"invalid size for {rel}")
        if not isinstance(mode, int) or isinstance(mode, bool) or mode < 0 or mode > 0o7777:
            raise AssertionError(f"invalid mode for {rel}")
        total_bytes += size
        normalized.append({"path": rel, "sha256": digest, "size": size, "mode": mode})
    if value["file_count"] != len(normalized):
        raise AssertionError("manifest file_count mismatch")
    if value["total_bytes"] != total_bytes:
        raise AssertionError("manifest total_bytes mismatch")
    return normalized, len(normalized), total_bytes


def collect(root: Path, manifest_path: Path) -> None:
    root = _root(root)
    entries = _manifest_entries(root)
    value = {
        "schema": SCHEMA,
        "toolchain": TOOLCHAIN,
        "file_count": len(entries),
        "total_bytes": sum(int(item["size"]) for item in entries),
        "files": entries,
    }
    payload = _canonical_bytes(value)
    if manifest_path.exists() and (manifest_path.is_symlink() or not manifest_path.is_file()):
        raise AssertionError("manifest destination must be a regular file path")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(payload)
    print(
        "RUST-023 collected Rust toolchain closure: "
        f"files={value['file_count']} bytes={value['total_bytes']} sha256={hashlib.sha256(payload).hexdigest()}"
    )


def _load_manifest(path: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    if path.is_symlink() or not path.is_file():
        raise AssertionError("manifest must be a regular file")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
        value = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssertionError("invalid manifest JSON") from exc
    if _canonical_bytes(value) != raw:
        raise AssertionError("manifest JSON is not canonical")
    entries, _, _ = _validate_manifest_object(value)
    assert isinstance(value, dict)
    return value, entries


def verify(root: Path, manifest_path: Path) -> None:
    root = _root(root)
    value, entries = _load_manifest(manifest_path)
    actual = _metadata(root)
    expected_paths = [str(item["path"]) for item in entries]
    if set(actual) != set(expected_paths):
        missing = sorted(set(expected_paths) - set(actual))
        extra = sorted(set(actual) - set(expected_paths))
        raise AssertionError(f"toolchain closure path mismatch missing={missing} extra={extra}")
    for item in entries:
        rel = str(item["path"])
        size, mode = actual[rel]
        if size != item["size"]:
            raise AssertionError(f"toolchain size mismatch: {rel}")
        if mode != item["mode"]:
            raise AssertionError(f"toolchain mode mismatch: {rel}")
        if _sha256(root / rel) != item["sha256"]:
            raise AssertionError(f"toolchain SHA-256 mismatch: {rel}")
    print(
        "RUST-023 exact Rust toolchain closure: GREEN "
        f"files={value['file_count']} bytes={value['total_bytes']}"
    )


def _write_manifest(path: Path, value: object, *, canonical: bool = True) -> None:
    if canonical:
        path.write_bytes(_canonical_bytes(value))
    else:
        path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def _must_reject(root: Path, manifest: Path, label: str) -> None:
    try:
        verify(root, manifest)
    except AssertionError:
        print(f"[GREEN] rejected {label}")
        return
    raise AssertionError(f"toolchain closure mutation unexpectedly accepted: {label}")


def selftest(root: Path, manifest_path: Path) -> None:
    root = _root(root)
    value, entries = _load_manifest(manifest_path)
    checks = 0
    with tempfile.TemporaryDirectory(prefix="axven-rust023-") as temp:
        base = Path(temp)

        mutated = dict(value)
        mutated["schema"] = "axven-rust-toolchain-closure-v0"
        path = base / "schema.json"
        _write_manifest(path, mutated)
        _must_reject(root, path, "schema substitution")
        checks += 1

        mutated = dict(value)
        mutated["toolchain"] = "1.98.1-x86_64-unknown-linux-gnu"
        path = base / "toolchain.json"
        _write_manifest(path, mutated)
        _must_reject(root, path, "toolchain identity substitution")
        checks += 1

        mutated = json.loads(json.dumps(value))
        current = mutated["files"][0]["sha256"]
        mutated["files"][0]["sha256"] = ("0" * 64 if current != "0" * 64 else "1" * 64)
        path = base / "digest.json"
        _write_manifest(path, mutated)
        _must_reject(root, path, "file digest mutation")
        checks += 1

        mutated = json.loads(json.dumps(value))
        mutated["files"][0]["size"] += 1
        mutated["total_bytes"] += 1
        path = base / "size.json"
        _write_manifest(path, mutated)
        _must_reject(root, path, "file size mutation")
        checks += 1

        mutated = json.loads(json.dumps(value))
        mutated["files"][0]["mode"] ^= 0o100
        path = base / "mode.json"
        _write_manifest(path, mutated)
        _must_reject(root, path, "file mode mutation")
        checks += 1

        mutated = json.loads(json.dumps(value))
        removed = mutated["files"].pop()
        mutated["file_count"] -= 1
        mutated["total_bytes"] -= removed["size"]
        path = base / "missing-entry.json"
        _write_manifest(path, mutated)
        _must_reject(root, path, "missing manifest entry")
        checks += 1

        mutated = json.loads(json.dumps(value))
        fake = {"path": "zz-axven-unexpected", "sha256": "0" * 64, "size": 0, "mode": 0o644}
        mutated["files"].append(fake)
        mutated["file_count"] += 1
        path = base / "extra-entry.json"
        _write_manifest(path, mutated)
        _must_reject(root, path, "extra manifest entry")
        checks += 1

        mutated = json.loads(json.dumps(value))
        mutated["files"].insert(1, dict(mutated["files"][0]))
        mutated["file_count"] += 1
        mutated["total_bytes"] += mutated["files"][0]["size"]
        path = base / "duplicate.json"
        _write_manifest(path, mutated)
        _must_reject(root, path, "duplicate manifest path")
        checks += 1

        path = base / "noncanonical.json"
        _write_manifest(path, value, canonical=False)
        _must_reject(root, path, "non-canonical manifest JSON")
        checks += 1

        synthetic = base / TOOLCHAIN
        synthetic.mkdir()
        target = synthetic / "real"
        target.write_bytes(b"rust023")
        (synthetic / "link").symlink_to("real")
        try:
            _metadata(synthetic)
        except AssertionError:
            print("[GREEN] rejected toolchain symlink")
        else:
            raise AssertionError("toolchain symlink unexpectedly accepted")
        checks += 1

    if checks != 10:
        raise AssertionError(checks)
    verify(root, manifest_path)
    print("RUST-023 Rust toolchain closure fail-closed contract: 10/10 GREEN")


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: rust_023_rust_toolchain_closure.py collect|verify|selftest TOOLCHAIN_ROOT MANIFEST")
    command = sys.argv[1]
    root = Path(sys.argv[2])
    manifest = Path(sys.argv[3])
    if command == "collect":
        collect(root, manifest)
    elif command == "verify":
        verify(root, manifest)
    elif command == "selftest":
        selftest(root, manifest)
    else:
        raise SystemExit(f"unknown command: {command}")


if __name__ == "__main__":
    main()
