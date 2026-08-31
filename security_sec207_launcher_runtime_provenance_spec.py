#!/usr/bin/env python3
"""SEC-207: Windows node launchers require validated runtime provenance."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import axven
import runtime_provenance

ROOT = Path(__file__).resolve().parent
CMD_LAUNCHERS = (
    "start-node1.cmd",
    "start-node2.cmd",
    "start-public-p2p-node.cmd",
)
PS_LAUNCHERS = (
    "canonical_node1_start.ps1",
    "canonical_node2_start.ps1",
)
MANIFEST_TARGETS = (
    "runtime_provenance.py",
    "ensure_runtime.ps1",
    "validate_windows.ps1",
    *CMD_LAUNCHERS,
    *PS_LAUNCHERS,
    "security_sec207_launcher_runtime_provenance_spec.py",
)


def main():
    checks = 0

    for name in CMD_LAUNCHERS:
        text = (ROOT / name).read_text(encoding="utf-8")
        lowered = text.lower()
        gate = 'powershell.exe -nologo -noprofile -noninteractive -file "%~dp0ensure_runtime.ps1"'
        assert gate in lowered, name
        assert "if errorlevel 1 exit /b 1" in lowered, name
        assert "if not exist .venv\\scripts\\python.exe call setup.cmd" not in lowered, name
        first_runtime = lowered.index(".venv\\scripts\\python.exe")
        assert lowered.index("ensure_runtime.ps1") < first_runtime, name
    checks += 1
    print("[GREEN] CMD node launchers gate first runtime use on SEC-207 preflight")

    forbidden_install = ("pip install", "-m venv", "py -3")
    for name in PS_LAUNCHERS:
        text = (ROOT / name).read_text(encoding="utf-8")
        lowered = text.lower()
        assert "ensure_runtime.ps1" in lowered, name
        assert all(token not in lowered for token in forbidden_install), name
        first_runtime = lowered.index(".venv\\scripts\\python.exe")
        assert lowered.index("ensure_runtime.ps1") < first_runtime, name
    checks += 1
    print("[GREEN] canonical PowerShell launchers contain no ambient installer bypass")

    ensure = (ROOT / "ensure_runtime.ps1").read_text(encoding="utf-8")
    ensure_lower = ensure.lower()
    assert "runtime_provenance.py check" in ensure_lower
    assert "doctor.py" in ensure_lower
    assert "validate_windows.ps1" in ensure_lower
    assert all(token not in ensure_lower for token in forbidden_install)
    assert ensure_lower.count("test-axvenvalidatedruntime") >= 3
    checks += 1
    print("[GREEN] runtime preflight checks receipt + doctor and repairs only through hardened validator")

    validator = (ROOT / "validate_windows.ps1").read_text(encoding="utf-8")
    validator_lower = validator.lower()
    assert "security_tail_runner.py" in validator_lower
    assert "runtime_provenance.py stamp" in validator_lower
    assert validator_lower.index("security_tail_runner.py") < validator_lower.index("runtime_provenance.py stamp")
    assert validator_lower.index("runtime_provenance.py stamp") < validator_lower.index("all axven checks green")
    checks += 1
    print("[GREEN] validator stamps provenance only after the complete security gate succeeds")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for index, name in enumerate(runtime_provenance.TRUST_INPUTS):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"trusted-{index}\n".encode("utf-8"))
        first = runtime_provenance.build_receipt(root, python_version=runtime_provenance.REQUIRED_PYTHON)
        assert first["schema"] == runtime_provenance.RECEIPT_SCHEMA
        assert set(first["inputs"]) == set(runtime_provenance.TRUST_INPUTS)
        changed = root / runtime_provenance.TRUST_INPUTS[0]
        changed.write_bytes(b"changed\n")
        second = runtime_provenance.build_receipt(root, python_version=runtime_provenance.REQUIRED_PYTHON)
        assert first != second
        try:
            runtime_provenance.build_receipt(root, python_version="3.13.14")
        except RuntimeError:
            pass
        else:
            raise AssertionError("runtime receipt accepted an unvalidated Python version")
    checks += 1
    print("[GREEN] runtime receipt is fail-closed and cryptographically bound to validation inputs")

    manifest = json.loads((ROOT / "release_manifest.json").read_text(encoding="utf-8"))
    missing = [name for name in MANIFEST_TARGETS if name not in manifest["files"]]
    assert not missing, missing
    checks += 1
    print("[GREEN] release manifest covers every SEC-207 runtime-provenance artifact")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] canonical chain identity unchanged")

    assert checks == 7, checks
    print("SEC-207 launcher runtime provenance: 7/7 GREEN")


if __name__ == "__main__":
    main()
