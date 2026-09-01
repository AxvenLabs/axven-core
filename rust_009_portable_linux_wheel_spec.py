#!/usr/bin/env python3
"""RUST-009: portable manylinux_2_28 native wheel contract."""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import zipfile
from email.parser import Parser

import axven

ROOT = Path(__file__).resolve().parent
WHEELHOUSE = ROOT / "wheelhouse-portable"
IMAGE = "quay.io/pypa/manylinux_2_28_x86_64@sha256:443eabd378e140996780a772e12c1a1ef10551da933fe76d74a1bab61f68a7b7"
EXPECTED_ROOT = "f9c17f4ac4ffe9b72aaebc1ed3a4c241f0316c29883a8adcbef610a92170e45d"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")


def _single_wheel() -> Path:
    wheels = sorted(WHEELHOUSE.glob("*.whl"))
    assert len(wheels) == 1, wheels
    wheel = wheels[0]
    assert wheel.stat().st_size > 0
    assert wheel.name.startswith("axven_native-0.1.0-")
    assert "abi3" in wheel.name, wheel.name
    assert "manylinux_2_28_x86_64" in wheel.name, wheel.name
    assert "manylinux_2_34" not in wheel.name, wheel.name
    return wheel


def _inspect_wheel(wheel: Path) -> str:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        assert names and len(names) == len(set(names))
        for name in names:
            path = PurePosixPath(name)
            assert not path.is_absolute(), name
            assert ".." not in path.parts, name
            assert "\\" not in name, name

        metadata_names = [n for n in names if n.endswith(".dist-info/METADATA")]
        wheel_names = [n for n in names if n.endswith(".dist-info/WHEEL")]
        native_names = [
            n for n in names
            if n.startswith("axven_native") and n.endswith(".so")
        ]
        assert len(metadata_names) == 1, metadata_names
        assert len(wheel_names) == 1, wheel_names
        assert len(native_names) == 1, native_names

        metadata = Parser().parsestr(archive.read(metadata_names[0]).decode("utf-8"))
        wheel_meta = Parser().parsestr(archive.read(wheel_names[0]).decode("utf-8"))
        assert metadata["Name"] == "axven-native"
        assert metadata["Version"] == "0.1.0"
        requires_python = metadata["Requires-Python"]
        assert requires_python is not None
        assert ">=3.13.15" in requires_python and "<3.14" in requires_python
        assert wheel_meta["Root-Is-Purelib"] == "false"
        tags = wheel_meta.get_all("Tag") or []
        assert tags
        assert any("abi3-manylinux_2_28_x86_64" in tag for tag in tags), tags
        assert all("manylinux_2_34" not in tag for tag in tags), tags

        with tempfile.TemporaryDirectory(prefix="axven-rust009-elf-") as temp:
            extension = Path(temp) / Path(native_names[0]).name
            extension.write_bytes(archive.read(native_names[0]))
            proc = subprocess.run(
                ["readelf", "--version-info", str(extension)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
            )
            versions = {
                (int(major), int(minor))
                for major, minor in re.findall(r"GLIBC_(\d+)\.(\d+)", proc.stdout)
            }
            assert versions, "no GLIBC symbol versions found"
            assert max(versions) <= (2, 28), sorted(versions)
    return native_names[0]


def _clean_install_probe(wheel: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="axven-rust009-install-") as temp:
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
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=temp_path,
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
        )
        result = json.loads(proc.stdout.strip().splitlines()[-1])
        assert result == {
            "boundary": "rust-001",
            "root": EXPECTED_ROOT,
            "duplicate_rejected": True,
        }, result


def _static_contract() -> None:
    workflow = (ROOT / ".github/workflows/native-portable-linux.yml").read_text(encoding="utf-8")
    doc = (ROOT / "RUST_009.md").read_text(encoding="utf-8")
    assert IMAGE in workflow
    assert IMAGE in doc
    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "--compatibility manylinux_2_28" in workflow
    assert "--locked" in workflow and "--release" in workflow
    assert "requirements-native-build.lock" in workflow
    forbidden = (
        "actions/upload-artifact",
        "maturin publish",
        "twine upload",
        "gh release",
        "softprops/action-gh-release",
    )
    lower = workflow.lower()
    for text in forbidden:
        assert text.lower() not in lower, text


def _production_contract() -> None:
    for name in PRODUCTION:
        source = (ROOT / name).read_text(encoding="utf-8")
        assert "axven_native" not in source, name

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    assert axven.CHAIN_CONFIG["smt_activation_height"] == 10_000
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2_000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5_000


def main() -> None:
    _static_contract()
    print("[GREEN] manylinux image is immutable-digest pinned and workflow is read-only")

    wheel = _single_wheel()
    native_name = _inspect_wheel(wheel)
    print(f"[GREEN] portable wheel metadata/tag/ELF floor verified: {wheel.name} :: {native_name}")

    _clean_install_probe(wheel)
    print("[GREEN] portable wheel clean-install native behavior is byte-exact and fail-closed")

    _production_contract()
    print("[GREEN] production remains Python-authoritative and canonical invariants are unchanged")
    print("RUST-009 portable Linux native wheel: 4/4 GREEN")


if __name__ == "__main__":
    main()
