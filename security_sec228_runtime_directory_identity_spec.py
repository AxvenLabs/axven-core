#!/usr/bin/env python3
"""SEC-228: validated runtime must live in a real local .venv directory."""
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

    assert hasattr(runtime_provenance, "_assert_local_runtime_directory")
    assert hasattr(runtime_provenance, "_is_reparse_point")
    checks += 1
    print("[GREEN] runtime provenance exposes local .venv identity guard")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = root / "external-runtime"
        target.mkdir()
        link = root / ".venv"
        if os.name != "nt":
            link.symlink_to(target, target_is_directory=True)
            try:
                runtime_provenance._assert_local_runtime_directory(root)
            except RuntimeError as exc:
                assert "symlink" in str(exc).lower() or "reparse" in str(exc).lower()
            else:
                raise AssertionError("symlinked .venv was accepted")
    checks += 1
    print("[GREEN] runtime provenance rejects a symlinked .venv directory")

    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    fake = SimpleNamespace(st_file_attributes=reparse_flag)
    assert runtime_provenance._is_reparse_point(fake)
    checks += 1
    print("[GREEN] runtime provenance recognizes Windows reparse-point metadata")

    validate_sh = (ROOT / "validate_linux_macos.sh").read_text(encoding="utf-8")
    ensure_sh = (ROOT / "ensure_runtime.sh").read_text(encoding="utf-8")
    assert "-L .venv" in validate_sh
    assert "-L .venv" in ensure_sh
    assert validate_sh.index("-L .venv") < validate_sh.index('venv_python=".venv/bin/python"')
    assert ensure_sh.index("-L .venv") < ensure_sh.index('venv_python=".venv/bin/python"')
    checks += 1
    print("[GREEN] POSIX validation and launch reject .venv symlinks before venv Python")

    validate_ps = (ROOT / "validate_windows.ps1").read_text(encoding="utf-8").lower()
    ensure_ps = (ROOT / "ensure_runtime.ps1").read_text(encoding="utf-8").lower()
    for source in (validate_ps, ensure_ps):
        assert "reparsepoint" in source
        assert 'get-item -literalpath ".venv" -force' in source
        assert source.index("reparsepoint") < source.index("& $python")
    checks += 1
    print("[GREEN] Windows validation and launch reject .venv reparse points before venv Python")

    source = (ROOT / "runtime_provenance.py").read_text(encoding="utf-8")
    stamp_body = source[source.index("def stamp("):source.index("def check(")]
    check_body = source[source.index("def check("):source.index("def main(")]
    assert "_assert_local_runtime_directory(root)" in stamp_body
    assert "_assert_local_runtime_directory(root)" in check_body
    checks += 1
    print("[GREEN] receipt stamp/check fail closed on runtime directory identity")

    manifest = json.loads((ROOT / "release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "runtime_provenance.py",
        "ensure_runtime.ps1",
        "ensure_runtime.sh",
        "validate_windows.ps1",
        "validate_linux_macos.sh",
        Path(__file__).name,
    ):
        assert manifest["files"].get(name) == _file_record(ROOT / name), name
    checks += 1
    print("[GREEN] release manifest authenticates SEC-228 production and regression bytes")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-228 leaves canonical chain identity unchanged")

    assert checks == 8, checks
    print("SEC-228 runtime directory identity: 8/8 GREEN")


if __name__ == "__main__":
    main()
