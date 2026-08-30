#!/usr/bin/env python3
"""SEC-170 Python runtime security-floor regression contract."""
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

import axven
import doctor


def main():
    checks=[]

    def green(name, condition):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    workflow=Path(".github/workflows/validation.yml").read_text(encoding="utf-8")
    pyproject=tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    green(
        "validation CI pins exact maintained Python 3.13.15",
        'python-version: "3.13.15"' in workflow
        and 'python-version: "3.11"' not in workflow,
    )
    green(
        "package metadata enforces the same Python security floor",
        pyproject["project"]["requires-python"] == ">=3.13.15,<3.14",
    )
    green(
        "doctor pins the canonical Python runtime interval",
        doctor.PYTHON_MIN == (3,13,15)
        and doctor.PYTHON_MAX_EXCLUSIVE == (3,14,0)
        and doctor.PYTHON_REQUIRED == ">=3.13.15,<3.14",
    )
    green(
        "pre-floor Python releases fail closed",
        not doctor._python_runtime_supported((3,10,21))
        and not doctor._python_runtime_supported((3,11,16))
        and not doctor._python_runtime_supported((3,12,14))
        and not doctor._python_runtime_supported((3,13,14)),
    )
    green(
        "canonical Python floor and later 3.13 patches remain supported",
        doctor._python_runtime_supported((3,13,15))
        and doctor._python_runtime_supported((3,13,99)),
    )
    green(
        "unvalidated next-minor Python fails closed",
        not doctor._python_runtime_supported((3,14,0))
        and not doctor._python_runtime_supported((4,0,0)),
    )
    green(
        "current validation interpreter satisfies the production floor",
        doctor._python_runtime_supported(sys.version_info),
    )
    doctor_result=doctor.run()
    green(
        "doctor reports the secure Python requirement as healthy",
        doctor_result["checks"]["python"]["ok"] is True
        and doctor_result["checks"]["python"]["required"] == ">=3.13.15,<3.14",
    )
    runtime_dependencies=pyproject["project"]["dependencies"]
    recovery_dependencies=pyproject["project"]["optional-dependencies"]["legacy-mldsa-recovery"]
    green(
        "runtime dependency security pins remain unchanged",
        "cryptography==50.0.1" in runtime_dependencies
        and "dilithium-py==1.4.0" not in runtime_dependencies
        and recovery_dependencies == ["dilithium-py==1.4.0"],
    )
    green(
        "Python runtime migration leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-170 Python runtime security floor: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
