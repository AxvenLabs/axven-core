#!/usr/bin/env python3
"""SEC-178 exact Python dependency-closure regression contract."""
from __future__ import annotations
import importlib.metadata
import re
import tomllib
from pathlib import Path
import axven, doctor

RUNTIME=["cryptography==50.0.1","cffi==2.1.1","pycparser==3.0"]
RECOVERY=["dilithium-py==1.4.0"]
BUILD=["setuptools==84.0.0","wheel==0.48.0","packaging==26.3"]


def _locked_versions(path):
    text=Path(path).read_text(encoding="utf-8")
    return dict(re.findall(r"(?m)^([A-Za-z0-9_.-]+)==([^ \\]+)",text))


def main():
    checks=[]
    def green(name,condition):
        assert condition,name; checks.append(name); print(f"[GREEN] {name}")
    requirements=[line.strip() for line in Path("requirements.txt").read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    pyproject=tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    project_deps=pyproject["project"]["dependencies"]
    recovery=pyproject["project"]["optional-dependencies"]["legacy-mldsa-recovery"]
    build_deps=pyproject["build-system"]["requires"]
    workflow=Path(".github/workflows/validation.yml").read_text(encoding="utf-8")
    runtime_lock=Path("requirements-ci-runtime-windows.lock").read_text(encoding="utf-8")
    toolchain_lock=Path("requirements-ci-toolchain.lock").read_text(encoding="utf-8")
    runtime_locked=_locked_versions("requirements-ci-runtime-windows.lock")
    toolchain_locked=_locked_versions("requirements-ci-toolchain.lock")
    green("requirements runtime dependency closure is exact",requirements==RUNTIME)
    green("package metadata runtime dependency closure is exact",project_deps==RUNTIME)
    green("legacy ML-DSA recovery closure is exact and optional",recovery==RECOVERY and RECOVERY[0] not in project_deps)
    green("PEP 517 build dependency closure is exact",build_deps==BUILD)
    green(
        "validation workflow uses the exact hash-locked closure, recovery extra, and pip check",
        runtime_locked == {
            "cryptography":"50.0.1",
            "cffi":"2.1.1",
            "pycparser":"3.0",
            "dilithium-py":"1.4.0",
        }
        and toolchain_locked == {
            "pip":"26.2.1",
            "setuptools":"84.0.0",
            "wheel":"0.48.0",
            "packaging":"26.3",
        }
        and runtime_lock.count("--hash=sha256:") == 5
        and toolchain_lock.count("--hash=sha256:") == 4
        and "requirements-ci-runtime-windows.lock" in workflow
        and "requirements-ci-toolchain.lock" in workflow
        and '.[legacy-mldsa-recovery]' in workflow
        and "python -m pip check" in workflow,
    )
    green("installed packaging build dependency matches the closure pin",importlib.metadata.version("packaging")=="26.3")
    green("installed cffi dependency matches the closure pin",importlib.metadata.version("cffi")=="2.1.1")
    green("installed pycparser dependency matches the closure pin",importlib.metadata.version("pycparser")=="3.0")
    result=doctor.run()["checks"]
    green("doctor enforces the cffi closure pin",result["cffi"]["ok"] is True and result["cffi"]["required"]=="2.1.1")
    green("doctor enforces the pycparser closure pin",result["pycparser"]["ok"] is True and result["pycparser"]["required"]=="3.0")
    green("installed legacy recovery backend is exact when validation enables it",result["legacy_mldsa_recovery"]["ok"] is True and result["legacy_mldsa_recovery"]["version"]=="1.4.0")
    green("dependency closure hardening leaves canonical chain identity unchanged",axven.CHAIN_ID=="axven-devnet-2" and axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae" and axven.Blockchain().tip.hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3")
    print(f"SEC-178 dependency closure pins: {len(checks)}/{len(checks)} GREEN")
if __name__=="__main__": main()
