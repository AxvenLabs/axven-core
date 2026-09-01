#!/usr/bin/env python3
"""RUST-006: cross-platform build/import contract for dormant axven_native."""
from __future__ import annotations

import importlib
import pathlib
import shutil
import sys
import sysconfig

ROOT = pathlib.Path(__file__).resolve().parent
CRATE = ROOT / "native" / "axven_native"
TARGET = CRATE / "target" / "release"
EXPECTED_ROOT = "f9c17f4ac4ffe9b72aaebc1ed3a4c241f0316c29883a8adcbef610a92170e45d"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")


def _built_library() -> pathlib.Path:
    if sys.platform == "win32":
        names = ("axven_native.dll", "libaxven_native.dll")
    elif sys.platform == "darwin":
        names = ("libaxven_native.dylib",)
    else:
        names = ("libaxven_native.so",)
    matches = [TARGET / name for name in names if (TARGET / name).is_file()]
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one built native library, got {matches!r}")
    return matches[0]


def _install_local_extension() -> pathlib.Path:
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    assert isinstance(suffix, str) and suffix, suffix
    source = _built_library()
    destination = ROOT / f"axven_native{suffix}"
    assert not destination.exists(), destination
    shutil.copyfile(source, destination)
    return destination


def main() -> None:
    checks = 0

    assert sys.version_info[:3] == (3, 13, 15), sys.version
    cargo = (CRATE / "Cargo.toml").read_text(encoding="utf-8")
    assert 'pyo3 = { version = "=0.29.2", features = ["abi3-py313"] }' in cargo
    assert 'sha2 = "=0.10.9"' in cargo
    native_pyproject = (CRATE / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires = ["maturin==1.15.0"]' in native_pyproject
    checks += 1
    print("[GREEN] Python/Rust/PyO3 native ABI pins remain explicit")

    workflow = (ROOT / ".github" / "workflows" / "native-cross-platform.yml").read_text(
        encoding="utf-8"
    )
    assert "contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "ubuntu-24.04" in workflow
    assert "windows-2025" in workflow
    assert "macos-15" in workflow
    assert "cargo build --release --locked" in workflow
    checks += 1
    print("[GREEN] CI matrix is read-only, cross-platform, and lockfile-bound")

    for name in PRODUCTION:
        source = (ROOT / name).read_text(encoding="utf-8")
        assert "axven_native" not in source, name
    checks += 1
    print("[GREEN] production Python modules remain native-import free")

    extension = _install_local_extension()
    assert extension.is_file() and extension.stat().st_size > 0
    importlib.invalidate_caches()
    axven_native = importlib.import_module("axven_native")
    assert axven_native.boundary_version() == "rust-001"
    checks += 1
    print(f"[GREEN] native extension imports from {sys.platform} using {extension.name}")

    row = ("00" * 32 + ":0", 1, "N" + "1" * 40, False, 1)
    root = axven_native.smt_root_mirror([row])
    assert root == EXPECTED_ROOT, (root, EXPECTED_ROOT)
    assert len(root) == 64 and root == root.lower()
    assert all(ch in "0123456789abcdef" for ch in root)
    checks += 1
    print("[GREEN] fixed Sparse-Merkle vector is byte-exact across the native ABI")

    try:
        axven_native.smt_root_mirror([row, row])
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate native outpoint must fail closed")
    checks += 1
    print("[GREEN] malformed duplicate FFI input fails closed")

    assert checks == 6, checks
    print(f"RUST-006 cross-platform native ABI ({sys.platform}): 6/6 GREEN")


if __name__ == "__main__":
    main()
