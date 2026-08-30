#!/usr/bin/env python3
"""SEC-178 exact Python dependency-closure regression contract."""
from __future__ import annotations

import importlib.metadata
import tomllib
from pathlib import Path

import axven
import doctor

RUNTIME = [
    "cryptography==50.0.1",
    "dilithium-py==1.4.0",
    "cffi==2.1.1",
    "pycparser==3.0",
]
BUILD = [
    "setuptools==84.0.0",
    "wheel==0.48.0",
    "packaging==26.3",
]


def main():
    checks=[]

    def green(name, condition):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    requirements=[
        line.strip()
        for line in Path("requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    pyproject=tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    project_deps=pyproject["project"]["dependencies"]
    build_deps=pyproject["build-system"]["requires"]
    workflow=Path(".github/workflows/validation.yml").read_text(encoding="utf-8")

    green("requirements runtime dependency closure is exact", requirements == RUNTIME)
    green("package metadata runtime dependency closure is exact", project_deps == RUNTIME)
    green("PEP 517 build dependency closure is exact", build_deps == BUILD)
    green(
        "validation workflow pins packaging and checks resolved compatibility",
        '"packaging==26.3"' in workflow
        and "python -m pip check" in workflow,
    )
    green(
        "installed packaging build dependency matches the closure pin",
        importlib.metadata.version("packaging") == "26.3",
    )
    green(
        "installed cffi dependency matches the closure pin",
        importlib.metadata.version("cffi") == "2.1.1",
    )
    green(
        "installed pycparser dependency matches the closure pin",
        importlib.metadata.version("pycparser") == "3.0",
    )

    result=doctor.run()["checks"]
    green(
        "doctor enforces the cffi closure pin",
        result["cffi"]["ok"] is True
        and result["cffi"]["required"] == "2.1.1"
        and result["cffi"]["version"] == "2.1.1",
    )
    green(
        "doctor enforces the pycparser closure pin",
        result["pycparser"]["ok"] is True
        and result["pycparser"]["required"] == "3.0"
        and result["pycparser"]["version"] == "3.0",
    )

    real_version=doctor.importlib.metadata.version
    def stale_version(name):
        if name == "cffi":
            return "2.1.0"
        if name == "pycparser":
            return "2.22"
        return real_version(name)
    doctor.importlib.metadata.version=stale_version
    try:
        stale=doctor.run()["checks"]
    finally:
        doctor.importlib.metadata.version=real_version
    green(
        "doctor fails closed on stale transitive dependency releases",
        stale["cffi"]["ok"] is False
        and stale["pycparser"]["ok"] is False,
    )
    green(
        "dependency closure hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-178 dependency closure pins: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
