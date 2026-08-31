#!/usr/bin/env python3
"""SEC-204: Windows setup must reuse the hardened provenance gate."""
from pathlib import Path

import axven


def main():
    checks = 0
    setup = Path("setup.cmd").read_text(encoding="utf-8")
    lowered = setup.lower()
    validator = Path("validate_windows.ps1").read_text(encoding="utf-8")

    assert 'powershell.exe -NoLogo -NoProfile -NonInteractive -File "%~dp0validate_windows.ps1"' in setup
    checks += 1
    print("[GREEN] setup delegates to the hardened Windows validator")

    assert "where powershell.exe >nul 2>&1" in lowered
    assert "if errorlevel 1" in lowered
    assert "exit /b 1" in lowered
    checks += 1
    print("[GREEN] setup fails closed when PowerShell or validation fails")

    forbidden = (
        "pip install",
        "-m venv",
        "py -3",
        "requirements-ci-",
        "--require-hashes",
        "--no-build-isolation",
        "pause",
        "executionpolicy bypass",
    )
    assert all(token not in lowered for token in forbidden), [token for token in forbidden if token in lowered]
    checks += 1
    print("[GREEN] setup contains no duplicate ambient installer or policy bypass")

    required_validator_tokens = (
        '$RequiredPython = "3.13.15"',
        "--only-binary=:all:",
        "--require-hashes",
        "requirements-ci-toolchain.lock",
        "requirements-ci-runtime-windows.lock",
        "--no-build-isolation --no-deps",
        "pip check",
        "doctor.py",
        "run_full_validation.py",
        "security_tail_runner.py",
    )
    assert all(token in validator for token in required_validator_tokens), [
        token for token in required_validator_tokens if token not in validator
    ]
    checks += 1
    print("[GREEN] delegated validator retains the complete provenance and validation gate")

    assert setup.rstrip().endswith("exit /b 0")
    checks += 1
    print("[GREEN] setup reports success only after the delegated gate returns successfully")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] canonical chain identity unchanged")

    assert checks == 6, checks
    print("SEC-204 Windows setup provenance: 6/6 GREEN")


if __name__ == "__main__":
    main()
