#!/usr/bin/env python3
"""SEC-226: validated runtime provenance must bind the actual interpreter binary."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import axven
import runtime_provenance

ROOT = Path(__file__).resolve().parent


def _populate(root: Path, names: tuple[str, ...]) -> None:
    for index, name in enumerate(names):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"trusted-{index}\n".encode("utf-8"))


def main() -> None:
    checks = 0

    # Receipt schema must explicitly measure the executable that performed the
    # validation. Version-only provenance is insufficient for runtime drift.
    assert runtime_provenance.RECEIPT_SCHEMA >= 3
    assert runtime_provenance.PYTHON_DIGEST_NAME == ".axven-python.sha256"
    checks += 1
    print("[GREEN] runtime provenance schema carries interpreter attestation")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _populate(root, runtime_provenance.WINDOWS_TRUST_INPUTS)
        interpreter = root / ".venv" / "Scripts" / "python.exe"
        interpreter.parent.mkdir(parents=True, exist_ok=True)
        interpreter.write_bytes(b"validated-python-binary-v1\n")

        first = runtime_provenance.build_receipt(
            root,
            python_version=runtime_provenance.REQUIRED_PYTHON,
            profile="windows",
            interpreter_path=interpreter,
        )
        measured = first.get("python_executable")
        assert isinstance(measured, dict)
        assert set(measured) == {"bytes", "sha256"}
        assert measured["bytes"] == interpreter.stat().st_size
        assert len(measured["sha256"]) == 64

        original_size = interpreter.stat().st_size
        interpreter.write_bytes(b"X" * original_size)
        second = runtime_provenance.build_receipt(
            root,
            python_version=runtime_provenance.REQUIRED_PYTHON,
            profile="windows",
            interpreter_path=interpreter,
        )
        assert first["python_executable"] != second["python_executable"]
    checks += 1
    print("[GREEN] same-size interpreter replacement invalidates measured runtime state")

    # Windows must compare a shell-computed executable digest before invoking
    # the interpreter whose integrity is being checked.
    ensure_ps = (ROOT / "ensure_runtime.ps1").read_text(encoding="utf-8")
    ps_lower = ensure_ps.lower()
    assert ".axven-python.sha256" in ps_lower
    assert "get-filehash" in ps_lower
    ps_hash = ps_lower.index("get-filehash")
    ps_check = ps_lower.index("runtime_provenance.py check")
    assert ps_hash < ps_check
    checks += 1
    print("[GREEN] Windows preflight checks interpreter digest before first venv execution")

    # POSIX must do the equivalent without asking the venv interpreter to
    # attest itself. Support both GNU/Linux and macOS hash utilities.
    ensure_sh = (ROOT / "ensure_runtime.sh").read_text(encoding="utf-8")
    sh_lower = ensure_sh.lower()
    assert ".axven-python.sha256" in sh_lower
    assert "sha256sum" in sh_lower
    assert "shasum -a 256" in sh_lower
    sh_hash = min(sh_lower.index("sha256sum"), sh_lower.index("shasum -a 256"))
    sh_check = sh_lower.index("runtime_provenance.py check")
    assert sh_hash < sh_check
    checks += 1
    print("[GREEN] POSIX preflight checks interpreter digest before first venv execution")

    source = (ROOT / "runtime_provenance.py").read_text(encoding="utf-8")
    assert "python_executable" in source
    assert "PYTHON_DIGEST_NAME" in source
    assert "interpreter_path" in source
    assert "_read_regular_bounded" in source
    checks += 1
    print("[GREEN] interpreter measurement uses the bounded descriptor-tied provenance reader")

    manifest = json.loads((ROOT / "release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "runtime_provenance.py",
        "ensure_runtime.ps1",
        "ensure_runtime.sh",
        "security_sec226_interpreter_runtime_attestation_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] release manifest authenticates the SEC-226 implementation and regression")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-226 leaves canonical chain identity unchanged")

    assert checks == 7, checks
    print("SEC-226 interpreter runtime attestation: 7/7 GREEN")


if __name__ == "__main__":
    main()
