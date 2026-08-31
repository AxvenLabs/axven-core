#!/usr/bin/env python3
"""SEC-219: Linux/macOS operator commands must require validated runtime provenance."""
from __future__ import annotations

import json
from pathlib import Path

import axven

ROOT = Path(__file__).resolve().parent


def main() -> None:
    checks = 0

    preflight = (ROOT / "ensure_runtime.sh").read_text(encoding="utf-8")
    assert "set -euo pipefail" in preflight
    assert 'venv_python=".venv/bin/python"' in preflight
    assert '[[ ! -x "$venv_python" ]]' in preflight
    assert '"$venv_python" runtime_provenance.py check' in preflight
    assert "validate_linux_macos.sh" in preflight
    checks += 1
    print("[GREEN] POSIX preflight fails closed and checks the exact validated .venv receipt")

    launcher = (ROOT / "axven-posix.sh").read_text(encoding="utf-8")
    assert "set -euo pipefail" in launcher
    gate_pos = launcher.index("bash ./ensure_runtime.sh")
    exec_pos = launcher.index('exec .venv/bin/python "$target" "$@"')
    assert gate_pos < exec_pos
    for command, target in (
        ("core", "axven_core.py"),
        ("cli", "axven_cli.py"),
        ("console", "axven_console.py"),
        ("doctor", "doctor.py"),
    ):
        assert command in launcher and target in launcher
    assert "unsupported Axven POSIX operator command" in launcher
    checks += 1
    print("[GREEN] supported POSIX operator commands cannot reach Python before provenance preflight")

    runbook = (ROOT / "RUNBOOK.md").read_text(encoding="utf-8")
    runbook_lower = runbook.lower()
    assert "exact python 3.13.15" in runbook_lower
    assert "bash validate_linux_macos.sh" in runbook
    assert "bash axven-posix.sh core" in runbook
    assert "bash axven-posix.sh cli" in runbook
    assert "python -m pip install --upgrade pip" not in runbook_lower
    assert "python -m pip install -e ." not in runbook_lower
    assert "python 3.11+" not in runbook_lower
    assert "source .venv/bin/activate" not in runbook_lower
    checks += 1
    print("[GREEN] runbook no longer advertises an executable ambient dependency/provenance bypass")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "bash validate_linux_macos.sh" in readme
    assert "bash axven-posix.sh core" in readme
    assert "POSIX provenance preflight" in readme
    assert "direct `.venv/bin/python` operator commands" in readme
    checks += 1
    print("[GREEN] public setup guidance directs POSIX operators through the attested boundary")

    manifest = json.loads((ROOT / "release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "ensure_runtime.sh",
        "axven-posix.sh",
        "RUNBOOK.md",
        "README.md",
        "security_sec219_posix_operator_runtime_provenance_spec.py",
    ):
        assert name in manifest["files"], f"release manifest missing SEC-219 boundary file: {name}"
    checks += 1
    print("[GREEN] release manifest authenticates every SEC-219 operator-boundary file")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-219 leaves canonical chain identity unchanged")

    assert checks == 6, checks
    print("SEC-219 POSIX operator runtime provenance: 6/6 GREEN")


if __name__ == "__main__":
    main()
