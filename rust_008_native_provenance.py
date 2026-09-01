#!/usr/bin/env python3
"""RUST-008: generate and verify ephemeral native wheel provenance candidates."""
from __future__ import annotations

import hashlib
from email.parser import Parser
import json
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent
WHEELHOUSE = ROOT / "wheelhouse"
INPUTS = (
    "native/axven_native/Cargo.toml",
    "native/axven_native/Cargo.lock",
    "native/axven_native/src/lib.rs",
    "requirements-native-build.lock",
)
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")
EXPECTED_ROOT = "f9c17f4ac4ffe9b72aaebc1ed3a4c241f0316c29883a8adcbef610a92170e45d"
HEX = frozenset("0123456789abcdef")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical(obj: object) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _lower_hex(value: str, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(ch in HEX for ch in value)


def _single_wheel() -> Path:
    wheels = sorted(WHEELHOUSE.glob("*.whl"))
    if len(wheels) != 1:
        raise AssertionError(f"expected exactly one wheel, got {wheels!r}")
    wheel = wheels[0]
    if not wheel.name.startswith("axven_native-0.1.0-"):
        raise AssertionError(wheel.name)
    if wheel.stat().st_size <= 0:
        raise AssertionError("empty wheel")
    return wheel


def _wheel_metadata(wheel: Path) -> dict:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if not names or len(names) != len(set(names)):
            raise AssertionError("empty or duplicate wheel members")
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or "\\" in name:
                raise AssertionError(f"unsafe wheel member: {name}")

        metadata_names = [n for n in names if n.endswith(".dist-info/METADATA")]
        wheel_names = [n for n in names if n.endswith(".dist-info/WHEEL")]
        native = [
            n
            for n in names
            if n.startswith("axven_native")
            and n.lower().endswith((".so", ".pyd", ".dylib"))
        ]
        if len(metadata_names) != 1 or len(wheel_names) != 1 or len(native) != 1:
            raise AssertionError((metadata_names, wheel_names, native))

        metadata = Parser().parsestr(archive.read(metadata_names[0]).decode("utf-8"))
        wheel_meta = Parser().parsestr(archive.read(wheel_names[0]).decode("utf-8"))
        if metadata["Name"] != "axven-native" or metadata["Version"] != "0.1.0":
            raise AssertionError((metadata["Name"], metadata["Version"]))
        requires_python = metadata["Requires-Python"]
        if requires_python is None or ">=3.13.15" not in requires_python or "<3.14" not in requires_python:
            raise AssertionError(requires_python)
        if wheel_meta["Root-Is-Purelib"] != "false":
            raise AssertionError("native wheel marked pure")
        tags = sorted(wheel_meta.get_all("Tag") or [])
        if not tags or not any("abi3" in tag for tag in tags):
            raise AssertionError(tags)

    return {
        "name": metadata["Name"],
        "version": metadata["Version"],
        "requires_python": requires_python,
        "tags": tags,
    }


def _command_text(args: list[str]) -> str:
    completed = subprocess.run(
        args,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _toolchain() -> dict:
    python_version = platform.python_version()
    rustc = _command_text(["rustc", "--version"])
    cargo = _command_text(["cargo", "--version"])
    maturin = _command_text([sys.executable, "-m", "maturin", "--version"])
    if python_version != "3.13.15":
        raise AssertionError(python_version)
    if not rustc.startswith("rustc 1.98.0 "):
        raise AssertionError(rustc)
    if not cargo.startswith("cargo 1.98.0 "):
        raise AssertionError(cargo)
    if maturin != "maturin 1.15.0":
        raise AssertionError(maturin)
    return {
        "python": python_version,
        "rustc": rustc,
        "cargo": cargo,
        "maturin": maturin,
    }


def _probe_native(wheel: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="axven-rust008-") as temp:
        temp_path = Path(temp)
        site = temp_path / "site"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                "--target",
                str(site),
                str(wheel.resolve()),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
        )
        code = f"""
import json
import sys
sys.path.insert(0, {str(site)!r})
import axven_native
rows = [("{'00' * 32}:0", 1, "N{'1' * 40}", False, 1)]
root = axven_native.smt_root_mirror(rows)
duplicate_rejected = False
try:
    axven_native.smt_root_mirror(rows + rows)
except ValueError:
    duplicate_rejected = True
print(json.dumps({{"boundary": axven_native.boundary_version(), "root": root, "duplicate_rejected": duplicate_rejected}}, sort_keys=True))
"""
        env = dict(os.environ)
        env["PYTHONNOUSERSITE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-c", code],
            cwd=temp_path,
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
        )
        probe = json.loads(completed.stdout.strip().splitlines()[-1])
    if probe != {
        "boundary": "rust-001",
        "root": EXPECTED_ROOT,
        "duplicate_rejected": True,
    }:
        raise AssertionError(probe)
    return probe


def _source_identity() -> dict:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    source_sha = os.environ.get("AXVEN_SOURCE_SHA", "").lower()
    github_sha = os.environ.get("GITHUB_SHA", "").lower()
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if repository != "AxvenLabs/axven-core":
        raise AssertionError(repository)
    if not _lower_hex(source_sha, 40) or not _lower_hex(github_sha, 40):
        raise AssertionError((source_sha, github_sha))
    if not run_id.isdigit() or not run_attempt.isdigit():
        raise AssertionError((run_id, run_attempt))
    checkout_sha = _command_text(["git", "rev-parse", "HEAD"]).lower()
    if checkout_sha != source_sha:
        raise AssertionError((checkout_sha, source_sha))
    return {
        "repository": repository,
        "commit": source_sha,
        "github_context_sha": github_sha,
        "run_id": int(run_id),
        "run_attempt": int(run_attempt),
    }


def _build_inputs() -> dict:
    result = {}
    for relative in INPUTS:
        path = ROOT / relative
        digest = _sha256_file(path)
        if not _lower_hex(digest, 64):
            raise AssertionError((relative, digest))
        result[relative] = digest
    return result


def _assert_production_python_only() -> None:
    for name in PRODUCTION:
        source = (ROOT / name).read_text(encoding="utf-8")
        if "axven_native" in source:
            raise AssertionError(name)


def _manifest(wheel: Path) -> dict:
    _assert_production_python_only()
    artifact_sha = _sha256_file(wheel)
    if not _lower_hex(artifact_sha, 64):
        raise AssertionError(artifact_sha)
    return {
        "schema": "axven-native-artifact-provenance-v1",
        "source": _source_identity(),
        "artifact": {
            "filename": wheel.name,
            "sha256": artifact_sha,
            "bytes": wheel.stat().st_size,
            "metadata": _wheel_metadata(wheel),
        },
        "build_inputs": _build_inputs(),
        "toolchain": _toolchain(),
        "native_probe": _probe_native(wheel),
        "production_consensus": "python",
    }


def generate(output: Path) -> None:
    wheel = _single_wheel()
    manifest = _manifest(wheel)
    output.write_bytes(_canonical(manifest))
    print(
        "RUST-008 provenance generated "
        f"sha256={manifest['artifact']['sha256']} bytes={manifest['artifact']['bytes']} "
        f"source={manifest['source']['commit']} file={manifest['artifact']['filename']}"
    )


def verify(output: Path) -> None:
    wheel = _single_wheel()
    raw = output.read_bytes()
    loaded = json.loads(raw.decode("utf-8"))
    if raw != _canonical(loaded):
        raise AssertionError("provenance is not canonical JSON")
    expected = _manifest(wheel)
    if loaded != expected:
        raise AssertionError("provenance does not match artifact/build identity")
    print("RUST-008 native artifact provenance candidate: GREEN")


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] not in {"generate", "verify"}:
        raise SystemExit("usage: rust_008_native_provenance.py {generate|verify} OUTPUT")
    output = Path(sys.argv[2])
    if sys.argv[1] == "generate":
        generate(output)
    else:
        verify(output)


if __name__ == "__main__":
    main()
