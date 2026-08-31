#!/usr/bin/env python3
"""Create and verify the SEC-213 validated Windows runtime receipt."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import stat
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent
REQUIRED_PYTHON = "3.13.15"
RECEIPT_SCHEMA = 2
RECEIPT_NAME = ".axven-runtime-provenance.json"
MAX_RECEIPT_BYTES = 32 * 1024
MAX_TRUST_INPUT_BYTES = 2 * 1024 * 1024
MAX_RELEASE_MANIFEST_BYTES = 1024 * 1024
MAX_RELEASE_FILES = 4096
MAX_RELEASE_FILE_BYTES = 64 * 1024 * 1024
MAX_RELEASE_TOTAL_BYTES = 256 * 1024 * 1024
HASH_CHUNK_BYTES = 64 * 1024
TRUST_INPUTS = (
    "setup.cmd",
    "validate_windows.ps1",
    "ensure_runtime.ps1",
    "release_manifest.json",
    "requirements-ci-toolchain.lock",
    "requirements-ci-runtime-windows.lock",
    "pyproject.toml",
    "doctor.py",
    "runtime_provenance.py",
)


def _same_file(before: os.stat_result, opened: os.stat_result) -> bool:
    """Return True only when both stat snapshots identify the same filesystem object."""
    try:
        return os.path.samestat(before, opened)
    except (AttributeError, OSError):
        return (before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino)


def _read_regular_bounded(path: Path, *, label: str, max_bytes: int, allow_empty: bool) -> bytes:
    """Read one regular file through a descriptor bound to the lstat-checked object."""
    try:
        before = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{label} is missing") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"{label} is not a regular non-symlink file")
    if before.st_size < 0 or before.st_size > max_bytes or (not allow_empty and before.st_size == 0):
        raise RuntimeError(f"{label} exceeds size budget or is invalid")

    data = bytearray()
    try:
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or not _same_file(before, opened)
                or opened.st_size != before.st_size
            ):
                raise RuntimeError(f"{label} changed before reading")
            remaining = opened.st_size
            while remaining:
                chunk = handle.read(min(HASH_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                data.extend(chunk)
                remaining -= len(chunk)
            extra = handle.read(1)
    except RuntimeError:
        raise
    except OSError as exc:
        raise RuntimeError(f"{label} is unreadable") from exc

    if remaining or extra:
        raise RuntimeError(f"{label} changed while reading")
    try:
        after = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{label} changed after reading") from exc
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or not _same_file(opened, after)
        or after.st_size != opened.st_size
    ):
        raise RuntimeError(f"{label} changed after reading")
    return bytes(data)


def _read_trust_input(path: Path, name: str) -> bytes:
    try:
        return _read_regular_bounded(
            path,
            label=f"provenance input {name}",
            max_bytes=MAX_TRUST_INPUT_BYTES,
            allow_empty=True,
        )
    except RuntimeError as exc:
        message = str(exc)
        if message.endswith(" is missing"):
            raise RuntimeError(f"missing provenance input: {name}") from exc
        if "not a regular non-symlink file" in message:
            raise RuntimeError(f"provenance input is not a regular non-symlink file: {name}") from exc
        if "exceeds size budget" in message:
            raise RuntimeError(f"provenance input exceeds size budget: {name}") from exc
        if "changed" in message:
            raise RuntimeError(f"provenance input changed while reading: {name}") from exc
        raise RuntimeError(f"provenance input is unreadable: {name}") from exc


def _read_receipt(path: Path) -> bytes:
    try:
        return _read_regular_bounded(
            path,
            label="runtime provenance receipt",
            max_bytes=MAX_RECEIPT_BYTES,
            allow_empty=False,
        )
    except RuntimeError as exc:
        message = str(exc)
        if message.endswith(" is missing"):
            raise RuntimeError("runtime provenance receipt is missing") from exc
        if "not a regular non-symlink file" in message:
            raise RuntimeError("runtime provenance receipt is not a regular non-symlink file") from exc
        if "exceeds size budget or is invalid" in message:
            raise RuntimeError("runtime provenance receipt is invalid") from exc
        if "changed" in message:
            raise RuntimeError("runtime provenance receipt changed while reading") from exc
        raise RuntimeError("runtime provenance receipt is unreadable") from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_manifest_name(name: object) -> PurePosixPath | None:
    if not isinstance(name, str) or not name or "\\" in name or "\x00" in name:
        return None
    pure = PurePosixPath(name)
    if pure.is_absolute() or str(pure) != name:
        return None
    if any(part in {"", ".", ".."} for part in pure.parts):
        return None
    return pure


def _verify_manifest_payloads(root: Path) -> None:
    """Verify every release-manifest payload before a validated runtime is trusted."""
    root = Path(root).resolve()
    manifest_path = root / "release_manifest.json"
    manifest_bytes = _read_trust_input(manifest_path, "release_manifest.json")
    if len(manifest_bytes) > MAX_RELEASE_MANIFEST_BYTES:
        raise RuntimeError("release manifest exceeds runtime verification size budget")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("release manifest is unreadable") from exc

    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(files, dict) or not files:
        raise RuntimeError("release manifest files must be a non-empty object")
    if len(files) > MAX_RELEASE_FILES:
        raise RuntimeError("release manifest exceeds runtime file-count budget")

    entries: list[tuple[str, PurePosixPath, str, int]] = []
    total_bytes = 0
    for name, meta in files.items():
        pure = _canonical_manifest_name(name)
        if pure is None or not isinstance(meta, dict):
            raise RuntimeError(f"invalid release manifest entry: {name!r}")
        expected_hash = meta.get("sha256")
        expected_bytes = meta.get("bytes")
        if (
            not isinstance(expected_hash, str)
            or len(expected_hash) != 64
            or any(ch not in "0123456789abcdef" for ch in expected_hash)
            or type(expected_bytes) is not int
            or expected_bytes < 0
        ):
            raise RuntimeError(f"invalid release manifest metadata: {name}")
        if expected_bytes > MAX_RELEASE_FILE_BYTES:
            raise RuntimeError(f"release payload exceeds per-file runtime budget: {name}")
        if total_bytes > MAX_RELEASE_TOTAL_BYTES - expected_bytes:
            raise RuntimeError("release manifest exceeds aggregate runtime verification budget")
        total_bytes += expected_bytes
        entries.append((name, pure, expected_hash, expected_bytes))

    for name, pure, expected_hash, expected_bytes in entries:
        path = root.joinpath(*pure.parts)
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise RuntimeError(f"missing release payload: {name}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"release payload is not a regular non-symlink file: {name}")
        if metadata.st_size != expected_bytes:
            raise RuntimeError(f"release payload size mismatch: {name}")
        try:
            path.resolve().relative_to(root)
        except ValueError as exc:
            raise RuntimeError(f"release payload escapes runtime root: {name}") from exc

        digest = hashlib.sha256()
        read_bytes = 0
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or not _same_file(metadata, opened)
                or opened.st_size != expected_bytes
            ):
                raise RuntimeError(f"release payload changed before hashing: {name}")
            while read_bytes < expected_bytes:
                chunk = handle.read(min(HASH_CHUNK_BYTES, expected_bytes - read_bytes))
                if not chunk:
                    break
                digest.update(chunk)
                read_bytes += len(chunk)
            extra = handle.read(1)
        if read_bytes != expected_bytes or extra:
            raise RuntimeError(f"release payload changed while hashing: {name}")
        if not hmac.compare_digest(digest.hexdigest(), expected_hash):
            raise RuntimeError(f"release payload hash mismatch: {name}")
        try:
            after = path.lstat()
        except OSError as exc:
            raise RuntimeError(f"release payload changed after hashing: {name}") from exc
        if (
            stat.S_ISLNK(after.st_mode)
            or not stat.S_ISREG(after.st_mode)
            or not _same_file(opened, after)
            or after.st_size != expected_bytes
        ):
            raise RuntimeError(f"release payload changed after hashing: {name}")


def build_receipt(root: Path, *, python_version: str) -> dict:
    if python_version != REQUIRED_PYTHON:
        raise RuntimeError(f"Python {REQUIRED_PYTHON} is required")
    inputs: dict[str, dict[str, int | str]] = {}
    for name in TRUST_INPUTS:
        data = _read_trust_input(root / name, name)
        inputs[name] = {"bytes": len(data), "sha256": _sha256(data)}
    return {
        "schema": RECEIPT_SCHEMA,
        "python_version": python_version,
        "inputs": inputs,
    }


def receipt_path(root: Path = ROOT) -> Path:
    return root / ".venv" / RECEIPT_NAME


def _assert_expected_interpreter(root: Path = ROOT) -> None:
    venv = (root / ".venv").resolve()
    executable = Path(sys.executable).resolve()
    if executable.parent.parent != venv:
        raise RuntimeError(f"runtime receipt must be managed by {venv}")


def stamp(root: Path = ROOT) -> None:
    _assert_expected_interpreter(root)
    _verify_manifest_payloads(root)
    receipt = build_receipt(root, python_version=platform.python_version())
    path = receipt_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(payload) > MAX_RECEIPT_BYTES:
        raise RuntimeError("runtime provenance receipt exceeds size budget")
    tmp = path.with_name(path.name + f".tmp-{os.getpid()}")
    try:
        with open(tmp, "xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
    print("Axven runtime provenance receipt: STAMPED")


def check(root: Path = ROOT) -> None:
    _assert_expected_interpreter(root)
    path = receipt_path(root)
    try:
        receipt_bytes = _read_receipt(path)
        actual = json.loads(receipt_bytes.decode("utf-8"))
    except RuntimeError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("runtime provenance receipt is unreadable") from exc
    _verify_manifest_payloads(root)
    expected = build_receipt(root, python_version=platform.python_version())
    if actual != expected:
        raise RuntimeError("runtime provenance receipt is stale or mismatched")
    print("Axven runtime provenance receipt: GREEN")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"stamp", "check"}:
        raise SystemExit("usage: runtime_provenance.py {stamp|check}")
    try:
        if sys.argv[1] == "stamp":
            stamp()
        else:
            check()
    except RuntimeError as exc:
        print(f"Axven runtime provenance: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
