#!/usr/bin/env python3
"""RUST-007: inspect and clean-install an unpublished axven_native wheel."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import zipfile
from email.parser import Parser

ROOT = Path(__file__).resolve().parent
WHEELHOUSE = ROOT / "wheelhouse"
EXPECTED_ROOT = "f9c17f4ac4ffe9b72aaebc1ed3a4c241f0316c29883a8adcbef610a92170e45d"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")


def _sha256_b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def _single_wheel() -> Path:
    wheels = sorted(WHEELHOUSE.glob("*.whl"))
    assert len(wheels) == 1, wheels
    wheel = wheels[0]
    assert wheel.name.startswith("axven_native-0.1.0-"), wheel.name
    assert wheel.stat().st_size > 0
    return wheel


def _inspect_wheel(wheel: Path) -> tuple[str, int]:
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    size = wheel.stat().st_size
    assert len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)

    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        assert names and len(names) == len(set(names))
        for name in names:
            path = PurePosixPath(name)
            assert not path.is_absolute(), name
            assert ".." not in path.parts, name
            assert "\\" not in name, name

        dist_info = "axven_native-0.1.0.dist-info"
        metadata_name = f"{dist_info}/METADATA"
        wheel_name = f"{dist_info}/WHEEL"
        record_name = f"{dist_info}/RECORD"
        for required in (metadata_name, wheel_name, record_name):
            assert required in names, required

        native = [
            name for name in names
            if name.startswith("axven_native") and name.lower().endswith((".so", ".pyd", ".dylib"))
        ]
        assert len(native) == 1, native

        metadata = Parser().parsestr(archive.read(metadata_name).decode("utf-8"))
        assert metadata["Name"] == "axven-native", metadata["Name"]
        assert metadata["Version"] == "0.1.0", metadata["Version"]
        requires_python = metadata["Requires-Python"]
        assert requires_python is not None
        assert ">=3.13.15" in requires_python and "<3.14" in requires_python

        wheel_metadata = Parser().parsestr(archive.read(wheel_name).decode("utf-8"))
        assert wheel_metadata["Root-Is-Purelib"] == "false"
        tags = wheel_metadata.get_all("Tag") or []
        assert tags and any("abi3" in tag for tag in tags), tags

        rows = list(csv.reader(io.StringIO(archive.read(record_name).decode("utf-8"))))
        record = {row[0]: row[1:] for row in rows}
        assert set(names) == set(record), (set(names) - set(record), set(record) - set(names))
        for name in names:
            hash_field, size_field = record[name]
            if name == record_name:
                assert hash_field == "" and size_field == ""
                continue
            data = archive.read(name)
            assert hash_field.startswith("sha256="), (name, hash_field)
            assert hash_field == "sha256=" + _sha256_b64url(data), name
            assert size_field == str(len(data)), name

    print(f"RUST-007 wheel SHA256 {digest} bytes={size} file={wheel.name}")
    return digest, size


def _clean_install_and_probe(wheel: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="axven-rust007-") as temp:
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
            cwd=temp_path,
            check=True,
        )
        probe = (
            "import axven_native; "
            "assert axven_native.boundary_version() == 'rust-001'; "
            "row=('00'*32+':0',1,'N'+'1'*40,False,1); "
            f"assert axven_native.smt_root_mirror([row]) == '{EXPECTED_ROOT}'; "
            "\ntry:\n axven_native.smt_root_mirror([row,row])\n"
            "except ValueError:\n pass\n"
            "else:\n raise AssertionError('duplicate outpoint must fail closed')\n"
            "print('RUST-007 clean installed wheel probe: GREEN')"
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = str(site)
        subprocess.run([sys.executable, "-c", probe], cwd=temp_path, env=env, check=True)


def main() -> None:
    assert sys.version_info[:3] == (3, 13, 15), sys.version

    for name in PRODUCTION:
        assert "axven_native" not in (ROOT / name).read_text(encoding="utf-8"), name
    print("[GREEN] production Python routing remains native-import free")

    lock = (ROOT / "requirements-native-build.lock").read_text(encoding="utf-8")
    assert "maturin==1.15.0" in lock
    assert lock.count("--hash=sha256:") == 3
    assert "94b26cc8e8aba61a5f2099715fe640e18c5f678e9a500408b38761263954228a" not in lock
    print("[GREEN] maturin build frontend is exact and wheel-hash locked with no sdist hash")

    workflow = (ROOT / ".github" / "workflows" / "native-wheel-package.yml").read_text(encoding="utf-8")
    assert "contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "--require-hashes" in workflow and "--only-binary=:all:" in workflow
    assert "maturin build" in workflow and "--locked" in workflow and "--release" in workflow
    lowered = workflow.lower()
    for forbidden in ("upload-artifact", "maturin publish", "twine upload", "pypi-token", "id-token: write"):
        assert forbidden not in lowered, forbidden
    print("[GREEN] wheel CI is read-only and contains no publish/upload path")

    wheel = _single_wheel()
    _digest, _size = _inspect_wheel(wheel)
    print("[GREEN] wheel archive metadata and RECORD integrity are exact")

    _clean_install_and_probe(wheel)
    print("[GREEN] wheel installs and runs from a clean temporary location without network access")
    print(f"RUST-007 native wheel package gate ({sys.platform}): 5/5 GREEN")


if __name__ == "__main__":
    main()
