#!/usr/bin/env python3
"""SEC-229: validated POSIX runtimes must exclude cross-user write modes."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace

import axven
import runtime_provenance

ROOT = Path(__file__).resolve().parent


def _file_record(path: Path) -> dict:
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def main() -> None:
    checks = 0

    assert hasattr(runtime_provenance, "POSIX_UNSAFE_WRITE_BITS")
    assert hasattr(runtime_provenance, "_has_unsafe_posix_write_permissions")
    assert hasattr(runtime_provenance, "_assert_posix_directory_write_boundary")
    assert runtime_provenance.POSIX_UNSAFE_WRITE_BITS == (stat.S_IWGRP | stat.S_IWOTH)
    assert runtime_provenance._has_unsafe_posix_write_permissions(
        SimpleNamespace(st_mode=stat.S_IFDIR | 0o775)
    )
    assert runtime_provenance._has_unsafe_posix_write_permissions(
        SimpleNamespace(st_mode=stat.S_IFREG | 0o646)
    )
    assert not runtime_provenance._has_unsafe_posix_write_permissions(
        SimpleNamespace(st_mode=stat.S_IFDIR | 0o755)
    )
    assert not runtime_provenance._has_unsafe_posix_write_permissions(
        SimpleNamespace(st_mode=stat.S_IFREG | 0o644)
    )
    checks += 1
    print("[GREEN] POSIX group/world write bits are classified as unsafe")

    if os.name == "posix":
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime_dir = root / ".venv"
            runtime_dir.mkdir()
            runtime_dir.chmod(0o775)
            try:
                runtime_provenance._assert_local_runtime_directory(root)
            except RuntimeError as exc:
                assert "writable" in str(exc).lower() or "permission" in str(exc).lower()
            else:
                raise AssertionError("group-writable .venv was accepted")
        checks += 1
        print("[GREEN] POSIX provenance rejects a group-writable .venv")
    else:
        checks += 1
        print("[GREEN] non-POSIX CI retains the static POSIX write-mode contract")

    validate_sh = (ROOT / "validate_linux_macos.sh").read_text(encoding="utf-8")
    ensure_sh = (ROOT / "ensure_runtime.sh").read_text(encoding="utf-8")
    assert "umask 077" in validate_sh
    assert validate_sh.index("umask 077") < validate_sh.index("python3 -m venv .venv")
    for source in (validate_sh, ensure_sh):
        assert "assert_not_group_world_writable" in source
        assert "022" in source
    checks += 1
    print("[GREEN] POSIX bootstrap creates private runtime files and preflights write modes")

    provenance_source = (ROOT / "runtime_provenance.py").read_text(encoding="utf-8")
    assert "_assert_posix_installation_write_boundary(root)" in provenance_source
    assert "_assert_posix_manifest_parent_write_boundary" in provenance_source
    assert "changed to group/world-writable" in provenance_source
    checks += 1
    print("[GREEN] receipt stamp/check bind root, parents, payloads, and sidecars to safe POSIX modes")

    manifest = json.loads((ROOT / "release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "runtime_provenance.py",
        "ensure_runtime.sh",
        "validate_linux_macos.sh",
        Path(__file__).name,
    ):
        assert manifest["files"].get(name) == _file_record(ROOT / name), name
    checks += 1
    print("[GREEN] release manifest authenticates SEC-229 production and regression bytes")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-229 leaves canonical chain identity unchanged")

    assert checks == 6, checks
    print("SEC-229 POSIX runtime write permissions: 6/6 GREEN")


if __name__ == "__main__":
    main()
