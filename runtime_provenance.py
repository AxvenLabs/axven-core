#!/usr/bin/env python3
"""Create and verify the SEC-207 validated Windows runtime receipt."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REQUIRED_PYTHON = "3.13.15"
RECEIPT_SCHEMA = 1
RECEIPT_NAME = ".axven-runtime-provenance.json"
MAX_RECEIPT_BYTES = 16 * 1024
TRUST_INPUTS = (
    "setup.cmd",
    "validate_windows.ps1",
    "ensure_runtime.ps1",
    "requirements-ci-toolchain.lock",
    "requirements-ci-runtime-windows.lock",
    "pyproject.toml",
    "doctor.py",
    "runtime_provenance.py",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_receipt(root: Path, *, python_version: str) -> dict:
    if python_version != REQUIRED_PYTHON:
        raise RuntimeError(f"Python {REQUIRED_PYTHON} is required")
    inputs: dict[str, dict[str, int | str]] = {}
    for name in TRUST_INPUTS:
        path = root / name
        if not path.is_file():
            raise RuntimeError(f"missing provenance input: {name}")
        data = path.read_bytes()
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
    receipt = build_receipt(root, python_version=platform.python_version())
    path = receipt_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
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
        size = path.stat().st_size
    except OSError as exc:
        raise RuntimeError("runtime provenance receipt is missing") from exc
    if not path.is_file() or size <= 0 or size > MAX_RECEIPT_BYTES:
        raise RuntimeError("runtime provenance receipt is invalid")
    try:
        actual = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("runtime provenance receipt is unreadable") from exc
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
