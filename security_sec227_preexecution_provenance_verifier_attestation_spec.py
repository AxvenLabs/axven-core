#!/usr/bin/env python3
"""SEC-227: runtime provenance verifier must be authenticated before execution."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import axven
import runtime_provenance

ROOT = Path(__file__).resolve().parent


def _file_record(path: Path) -> dict:
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def main() -> None:
    checks = 0

    assert (
        runtime_provenance.PROVENANCE_VERIFIER_DIGEST_NAME
        == ".axven-runtime-provenance.sha256"
    )
    checks += 1
    print("[GREEN] runtime provenance publishes a dedicated verifier digest")

    ensure_ps = (ROOT / "ensure_runtime.ps1").read_text(encoding="utf-8")
    ps = ensure_ps.lower()
    assert ".axven-runtime-provenance.sha256" in ps
    assert "get-filehash" in ps
    verifier_hash = ps.index("runtime_provenance.py", ps.index("get-filehash"))
    verifier_exec = ps.index("& $python runtime_provenance.py check")
    assert verifier_hash < verifier_exec
    checks += 1
    print("[GREEN] Windows hashes runtime_provenance.py before first verifier execution")

    ensure_sh = (ROOT / "ensure_runtime.sh").read_text(encoding="utf-8")
    sh = ensure_sh.lower()
    assert ".axven-runtime-provenance.sha256" in sh
    assert 'verifier_path="runtime_provenance.py"' in sh
    hash_candidates = [
        sh.find('sha256sum -- "$verifier_path"'),
        sh.find('shasum -a 256 -- "$verifier_path"'),
    ]
    assert any(index >= 0 for index in hash_candidates)
    verifier_hash = min(index for index in hash_candidates if index >= 0)
    verifier_exec = sh.index('"$venv_python" runtime_provenance.py check')
    assert verifier_hash < verifier_exec
    checks += 1
    print("[GREEN] POSIX hashes runtime_provenance.py before first verifier execution")

    validate_ps = (ROOT / "validate_windows.ps1").read_text(encoding="utf-8").lower()
    assert ".axven-runtime-provenance.sha256" in validate_ps
    assert validate_ps.index("get-filehash") < validate_ps.index('& $python -c')
    checks += 1
    print("[GREEN] Windows existing-runtime validation rejects verifier drift before venv Python")

    validate_sh = (ROOT / "validate_linux_macos.sh").read_text(encoding="utf-8").lower()
    assert ".axven-runtime-provenance.sha256" in validate_sh
    assert 'verifier_path="runtime_provenance.py"' in validate_sh
    verifier_hash = validate_sh.find('sha256sum -- "$verifier_path"')
    if verifier_hash < 0:
        verifier_hash = validate_sh.find('shasum -a 256 -- "$verifier_path"')
    assert verifier_hash >= 0
    assert verifier_hash < validate_sh.index('venv_version="$($venv_python')
    checks += 1
    print("[GREEN] POSIX existing-runtime validation rejects verifier drift before venv Python")

    source = (ROOT / "runtime_provenance.py").read_text(encoding="utf-8")
    assert "PROVENANCE_VERIFIER_DIGEST_NAME" in source
    assert "provenance_verifier_digest_path" in source
    assert "runtime_provenance.py" in source
    assert "Python provenance verifier digest is stale or mismatched" in source
    checks += 1
    print("[GREEN] receipt stamping/checking binds the shell verifier digest to measured trust input")

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
    print("[GREEN] release manifest authenticates SEC-227 production and regression bytes")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-227 leaves canonical chain identity unchanged")

    assert checks == 8, checks
    print("SEC-227 pre-execution provenance verifier attestation: 8/8 GREEN")


if __name__ == "__main__":
    main()
