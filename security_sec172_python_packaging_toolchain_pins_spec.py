#!/usr/bin/env python3
"""SEC-172 immutable Python packaging-toolchain regression contract."""
from __future__ import annotations

import importlib.metadata
import tomllib
from pathlib import Path

import axven

PIP = "26.2.1"
SETUPTOOLS = "84.0.0"
WHEEL = "0.48.0"
PACKAGING = "26.3"


def main():
    checks=[]

    def green(name, condition):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    workflow=Path(".github/workflows/validation.yml").read_text(encoding="utf-8")
    pyproject=tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    build_requires=pyproject["build-system"]["requires"]

    green(
        "PEP 517 build backend dependency closure is exactly pinned",
        build_requires == [
            f"setuptools=={SETUPTOOLS}",
            f"wheel=={WHEEL}",
            f"packaging=={PACKAGING}",
        ],
    )
    green(
        "open-ended packaging build requirements are absent",
        all(">=" not in item and "~=" not in item and ">" not in item
            for item in build_requires),
    )
    pinned_install=(
        f'python -m pip install "pip=={PIP}" '
        f'"setuptools=={SETUPTOOLS}" "wheel=={WHEEL}" '
        f'"packaging=={PACKAGING}"'
    )
    green(
        "validation CI installs an exact packaging toolchain closure",
        pinned_install in workflow,
    )
    green(
        "validation CI never upgrades pip to an ambient latest release",
        "pip install --upgrade pip" not in workflow
        and "pip install -U pip" not in workflow,
    )
    green(
        "validation CI keeps the exact Python runtime pin",
        'python-version: "3.13.15"' in workflow,
    )
    green(
        "active CI pip version matches the immutable pin",
        importlib.metadata.version("pip") == PIP,
    )
    green(
        "active CI setuptools version matches the immutable pin",
        importlib.metadata.version("setuptools") == SETUPTOOLS,
    )
    green(
        "active CI wheel version matches the immutable pin",
        importlib.metadata.version("wheel") == WHEEL,
    )
    green(
        "active CI packaging version matches the immutable build pin",
        importlib.metadata.version("packaging") == PACKAGING,
    )
    runtime_dependencies=pyproject["project"]["dependencies"]
    green(
        "original runtime security pins remain present",
        "cryptography==50.0.1" in runtime_dependencies
        and "dilithium-py==1.4.0" in runtime_dependencies,
    )
    green(
        "packaging hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-172 Python packaging toolchain pins: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
