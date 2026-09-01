#!/usr/bin/env python3
"""Create and verify platform-bound validated runtime provenance receipts."""
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
RECEIPT_SCHEMA = 3
RECEIPT_NAME = ".axven-runtime-provenance.json"
PYTHON_DIGEST_NAME = ".axven-python.sha256"
PROVENANCE_VERIFIER_DIGEST_NAME = ".axven-runtime-provenance.sha256"
MAX_RECEIPT_BYTES = 32 * 1024
MAX_PYTHON_DIGEST_BYTES = 128
MAX_PROVENANCE_VERIFIER_DIGEST_BYTES = 128
MAX_INTERPRETER_BYTES = 64 * 1024 * 1024
MAX_TRUST_INPUT_BYTES = 2 * 1024 * 1024
MAX_RELEASE_MANIFEST_BYTES = 1024 * 1024
MAX_RELEASE_FILES = 4096
MAX_RELEASE_FILE_BYTES = 64 * 1024 * 1024
MAX_RELEASE_TOTAL_BYTES = 256 * 1024 * 1024
HASH_CHUNK_BYTES = 64 * 1024
POSIX_UNSAFE_WRITE_BITS = stat.S_IWGRP | stat.S_IWOTH
WINDOWS_TRUST_INPUTS = (
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
POSIX_TRUST_INPUTS = (
    "validate_linux_macos.sh",
    "release_manifest.json",
    "requirements-ci-toolchain.lock",
    "requirements-ci-runtime-posix.lock",
    "pyproject.toml",
    "doctor.py",
    "runtime_provenance.py",
)
# Backward-compatible SEC-213 API: existing tests/callers use TRUST_INPUTS
# to mean the original Windows validated-runtime boundary.
TRUST_INPUTS = WINDOWS_TRUST_INPUTS


def _same_file(before: os.stat_result, opened: os.stat_result) -> bool:
    """Return True only when both stat snapshots identify the same filesystem object."""
    try:
        return os.path.samestat(before, opened)
    except (AttributeError, OSError):
        return (before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino)


def _is_reparse_point(metadata: object) -> bool:
    """Return True for Windows filesystem reparse-point metadata."""
    attributes = getattr(metadata, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _has_unsafe_posix_write_permissions(metadata: object) -> bool:
    """Return True when POSIX group/other write permission is present."""
    return bool(getattr(metadata, "st_mode", 0) & POSIX_UNSAFE_WRITE_BITS)


def _assert_posix_directory_write_boundary(path: Path, *, label: str) -> None:
    """Require one POSIX trust-boundary directory to exclude other writers."""
    if os.name != "posix":
        return
    try:
        metadata = Path(path).lstat()
    except OSError as exc:
        raise RuntimeError(f"{label} is missing") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(f"{label} is not a real directory")
    if _has_unsafe_posix_write_permissions(metadata):
        raise RuntimeError(f"{label} is group/world-writable")


def _assert_posix_installation_write_boundary(root: Path = ROOT) -> None:
    """Require the installation root and .venv root to exclude other writers."""
    if os.name != "posix":
        return
    root_path = Path(os.path.abspath(root))
    _assert_posix_directory_write_boundary(root_path, label="Axven runtime root")
    _assert_posix_directory_write_boundary(
        root_path / ".venv", label="validated runtime directory"
    )


def _assert_posix_manifest_parent_write_boundary(
    root: Path, path: Path, *, label: str
) -> None:
    """Reject writable/symlink directory components beneath the runtime root."""
    if os.name != "posix":
        return
    root_path = Path(os.path.abspath(root))
    path_path = Path(os.path.abspath(path))
    try:
        relative = path_path.relative_to(root_path)
    except ValueError as exc:
        raise RuntimeError(f"{label} escapes runtime root") from exc
    current = root_path
    _assert_posix_directory_write_boundary(current, label="Axven runtime root")
    for part in relative.parts[:-1]:
        current = current / part
        _assert_posix_directory_write_boundary(
            current, label=f"{label} parent directory"
        )


def _assert_local_runtime_directory(root: Path = ROOT) -> None:
    """Require .venv to be a real directory rooted directly under root."""
    runtime_dir = Path(root) / ".venv"
    try:
        metadata = runtime_dir.lstat()
    except OSError as exc:
        raise RuntimeError("validated runtime directory is missing") from exc
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        raise RuntimeError(
            "validated runtime directory is a symlink or reparse point"
        )
    if not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("validated runtime path is not a directory")
    if os.name == "posix" and _has_unsafe_posix_write_permissions(metadata):
        raise RuntimeError("validated runtime directory is group/world-writable")
    try:
        resolved_root = Path(root).resolve(strict=True)
        resolved_runtime = runtime_dir.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RuntimeError("validated runtime directory is unresolved") from exc
    if resolved_runtime.parent != resolved_root:
        raise RuntimeError("validated runtime directory escapes runtime root")


def _read_regular_bounded(path: Path, *, label: str, max_bytes: int, allow_empty: bool) -> bytes:
    """Read one regular file through a descriptor bound to the lstat-checked object."""
    try:
        before = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{label} is missing") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"{label} is not a regular non-symlink file")
    if os.name == "posix" and _has_unsafe_posix_write_permissions(before):
        raise RuntimeError(f"{label} changed to group/world-writable")
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
                or (os.name == "posix" and _has_unsafe_posix_write_permissions(opened))
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
        or (os.name == "posix" and _has_unsafe_posix_write_permissions(after))
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
    _assert_posix_manifest_parent_write_boundary(
        root, manifest_path, label="release manifest"
    )
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
        _assert_posix_manifest_parent_write_boundary(
            root, path, label=f"release payload {name}"
        )
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise RuntimeError(f"missing release payload: {name}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"release payload is not a regular non-symlink file: {name}")
        if os.name == "posix" and _has_unsafe_posix_write_permissions(metadata):
            raise RuntimeError(f"release payload changed to group/world-writable: {name}")
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
                or (os.name == "posix" and _has_unsafe_posix_write_permissions(opened))
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
            or (os.name == "posix" and _has_unsafe_posix_write_permissions(after))
        ):
            raise RuntimeError(f"release payload changed after hashing: {name}")


def _trust_inputs_for_profile(profile: str) -> tuple[str, ...]:
    if profile == "windows":
        return WINDOWS_TRUST_INPUTS
    if profile == "posix":
        return POSIX_TRUST_INPUTS
    raise RuntimeError(f"unsupported runtime provenance profile: {profile}")


def _runtime_profile() -> str:
    system = platform.system()
    if os.name == "nt" or system == "Windows":
        return "windows"
    if system in {"Linux", "Darwin"}:
        return "posix"
    raise RuntimeError(f"unsupported runtime provenance platform: {system}")


def _measure_interpreter(interpreter_path: Path | str) -> dict[str, int | str]:
    try:
        resolved = Path(interpreter_path).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RuntimeError("Python interpreter is missing or unresolved") from exc
    data = _read_regular_bounded(
        resolved,
        label="Python interpreter",
        max_bytes=MAX_INTERPRETER_BYTES,
        allow_empty=False,
    )
    return {"bytes": len(data), "sha256": _sha256(data)}


def build_receipt(
    root: Path,
    *,
    python_version: str,
    profile: str = "windows",
    interpreter_path: Path | str | None = None,
) -> dict:
    if python_version != REQUIRED_PYTHON:
        raise RuntimeError(f"Python {REQUIRED_PYTHON} is required")
    inputs: dict[str, dict[str, int | str]] = {}
    for name in _trust_inputs_for_profile(profile):
        data = _read_trust_input(root / name, name)
        inputs[name] = {"bytes": len(data), "sha256": _sha256(data)}
    if interpreter_path is None:
        interpreter_path = Path(sys.executable)
    return {
        "schema": RECEIPT_SCHEMA,
        "python_version": python_version,
        "python_executable": _measure_interpreter(interpreter_path),
        "inputs": inputs,
    }


def receipt_path(root: Path = ROOT) -> Path:
    return root / ".venv" / RECEIPT_NAME


def python_digest_path(root: Path = ROOT) -> Path:
    return root / ".venv" / PYTHON_DIGEST_NAME


def provenance_verifier_digest_path(root: Path = ROOT) -> Path:
    return root / ".venv" / PROVENANCE_VERIFIER_DIGEST_NAME


def _read_python_digest(path: Path) -> str:
    try:
        raw = _read_regular_bounded(
            path,
            label="Python interpreter digest",
            max_bytes=MAX_PYTHON_DIGEST_BYTES,
            allow_empty=False,
        )
        value = raw.decode("ascii").strip()
    except UnicodeError as exc:
        raise RuntimeError("Python interpreter digest is invalid") from exc
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise RuntimeError("Python interpreter digest is invalid")
    return value


def _read_provenance_verifier_digest(path: Path) -> str:
    try:
        raw = _read_regular_bounded(
            path,
            label="Python provenance verifier digest",
            max_bytes=MAX_PROVENANCE_VERIFIER_DIGEST_BYTES,
            allow_empty=False,
        )
        value = raw.decode("ascii").strip()
    except UnicodeError as exc:
        raise RuntimeError("Python provenance verifier digest is invalid") from exc
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise RuntimeError("Python provenance verifier digest is invalid")
    return value


def _atomic_write_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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


def _assert_expected_interpreter(root: Path = ROOT) -> None:
    # Preserve the lexical venv path on POSIX: venv/bin/python is normally a
    # symlink to the base interpreter. Binary identity is measured separately.
    venv = Path(os.path.abspath(root / ".venv"))
    executable = Path(os.path.abspath(sys.executable))
    profile = _runtime_profile()
    relative = Path("Scripts/python.exe") if profile == "windows" else Path("bin/python")
    expected = venv / relative
    if os.path.normcase(str(executable)) != os.path.normcase(str(expected)):
        raise RuntimeError(f"runtime receipt must be managed by {expected}")


def stamp(root: Path = ROOT, *, profile: str | None = None) -> None:
    if profile is None:
        profile = _runtime_profile()
    _assert_posix_installation_write_boundary(root)
    _assert_local_runtime_directory(root)
    _assert_expected_interpreter(root)
    _verify_manifest_payloads(root)
    receipt = build_receipt(
        root,
        python_version=platform.python_version(),
        profile=profile,
        interpreter_path=Path(sys.executable),
    )
    path = receipt_path(root)
    payload = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(payload) > MAX_RECEIPT_BYTES:
        raise RuntimeError("runtime provenance receipt exceeds size budget")
    _atomic_write_private(path, payload)
    digest = receipt["python_executable"]["sha256"]
    _atomic_write_private(python_digest_path(root), (digest + "\n").encode("ascii"))
    verifier_digest = receipt["inputs"]["runtime_provenance.py"]["sha256"]
    _atomic_write_private(
        provenance_verifier_digest_path(root),
        (verifier_digest + "\n").encode("ascii"),
    )
    print("Axven runtime provenance receipt: STAMPED")


def check(root: Path = ROOT, *, profile: str | None = None) -> None:
    if profile is None:
        profile = _runtime_profile()
    _assert_posix_installation_write_boundary(root)
    _assert_local_runtime_directory(root)
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
    expected = build_receipt(
        root,
        python_version=platform.python_version(),
        profile=profile,
        interpreter_path=Path(sys.executable),
    )
    published_digest = _read_python_digest(python_digest_path(root))
    if not hmac.compare_digest(published_digest, expected["python_executable"]["sha256"]):
        raise RuntimeError("Python interpreter digest is stale or mismatched")
    published_verifier_digest = _read_provenance_verifier_digest(
        provenance_verifier_digest_path(root)
    )
    expected_verifier_digest = expected["inputs"]["runtime_provenance.py"]["sha256"]
    if not hmac.compare_digest(published_verifier_digest, expected_verifier_digest):
        raise RuntimeError("Python provenance verifier digest is stale or mismatched")
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
