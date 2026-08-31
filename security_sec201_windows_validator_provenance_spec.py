#!/usr/bin/env python3
"""SEC-201: manual Windows validation must preserve CI dependency provenance."""
from __future__ import annotations

from pathlib import Path

import axven

SCRIPT = Path("validate_windows.ps1")


def main():
    checks=[]

    def green(label, condition=True):
        assert condition,label
        checks.append(label)
        print("[GREEN]",label)

    text=SCRIPT.read_text(encoding="utf-8")

    first_install=min(
        text.index("requirements-ci-toolchain.lock"),
        text.index("requirements-ci-runtime-windows.lock"),
    )
    runtime_probe=text.index("py -3.13 -I -S -c")
    green(
        "exact Python 3.13.15 is isolated and checked before any dependency installation",
        '$RequiredPython = "3.13.15"' in text
        and runtime_probe < first_install
        and "platform.python_version() == '$RequiredPython'" in text
        and "py -3.13 -I -S -m venv .venv" in text,
    )

    green(
        "ambient pip upgrade and version-only editable bootstrap are absent",
        "pip install --upgrade pip" not in text
        and "pip install -e ." not in text,
    )

    green(
        "manual toolchain install is wheel-only and hash-locked",
        "pip install --no-deps --only-binary=:all: --require-hashes -r requirements-ci-toolchain.lock" in text,
    )

    green(
        "manual runtime install is wheel-only and hash-locked",
        "pip install --no-deps --only-binary=:all: --require-hashes -r requirements-ci-runtime-windows.lock" in text,
    )

    green(
        "editable Axven install cannot resolve ambient build or runtime dependencies",
        'pip install --no-build-isolation --no-deps -e ".[legacy-mldsa-recovery]"' in text,
    )

    pip_check=text.index("-m pip check")
    doctor=text.index("doctor.py")
    full=text.index("run_full_validation.py")
    tail=text.index("security_tail_runner.py")
    green(
        "dependency closure is checked before doctor and validation work",
        pip_check < doctor < full < tail,
    )

    green(
        "manual Windows gate includes the complete SEC-076+ security tail",
        "=== SEC-076+ SECURITY TAIL ===" in text
        and "Axven security tail failed" in text,
    )

    remove=text.index("Remove-Item -LiteralPath $VenvPath")
    recreate=text.index("py -3.13 -I -S -m venv .venv")
    first_package=text.index("& $Python -m pip")
    green(
        "stale Windows virtualenv state is removed before isolated reconstruction and package mutation",
        "$ExistingVenv = Get-Item -LiteralPath $VenvPath -Force -ErrorAction SilentlyContinue" in text
        and "[IO.FileAttributes]::ReparsePoint" in text
        and remove < recreate < first_package
        and "if (-not (Test-Path \".venv\"))" not in text
        and text.count("platform.python_version() == '$RequiredPython'") == 2,
    )

    green(
        "SEC-201 leaves canonical chain and PQ activation identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2000
        and axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5000
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    assert len(checks)==9,len(checks)
    print("SEC-201 Windows validator provenance: 9/9 GREEN")


if __name__ == "__main__":
    main()
