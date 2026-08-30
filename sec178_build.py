#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(".")
REQ = ROOT / "requirements.txt"
PYPROJECT = ROOT / "pyproject.toml"
DOCTOR = ROOT / "doctor.py"
SEC170 = ROOT / "security_sec170_python_runtime_security_floor_spec.py"
SEC172 = ROOT / "security_sec172_python_packaging_toolchain_pins_spec.py"
SEC178 = ROOT / "security_sec178_dependency_closure_pins_spec.py"
WORKFLOW = ROOT / ".github/workflows/validation.yml"
MANIFEST = ROOT / "release_manifest.json"
SELF = Path(__file__)

REQ_TEXT = """cryptography==50.0.1
dilithium-py==1.4.0
cffi==2.1.1
pycparser==3.0
"""
REQ.write_text(REQ_TEXT, encoding="utf-8", newline="\n")

pyproject = PYPROJECT.read_text(encoding="utf-8")
pyproject = pyproject.replace(
    'requires = ["setuptools==84.0.0", "wheel==0.48.0"]',
    'requires = ["setuptools==84.0.0", "wheel==0.48.0", "packaging==26.3"]',
    1,
)
old_deps = '''dependencies = [
  "cryptography==50.0.1",
  "dilithium-py==1.4.0",
]
'''
new_deps = '''dependencies = [
  "cryptography==50.0.1",
  "dilithium-py==1.4.0",
  "cffi==2.1.1",
  "pycparser==3.0",
]
'''
if old_deps not in pyproject:
    raise SystemExit("pyproject dependency anchor missing")
pyproject = pyproject.replace(old_deps, new_deps, 1)
PYPROJECT.write_text(pyproject, encoding="utf-8", newline="\n")

workflow = '''name: Axven Validation

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: windows-latest

    env:
      PYTHONUTF8: "1"
      PYTHONIOENCODING: "utf-8"

    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          persist-credentials: false

      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
        with:
          python-version: "3.13.15"

      - name: Enable UTF-8
        shell: pwsh
        run: |
          chcp 65001

      - name: Install pinned packaging toolchain
        shell: pwsh
        run: |
          python -m pip install "pip==26.2.1" "setuptools==84.0.0" "wheel==0.48.0" "packaging==26.3"
          python -m pip install -e .
          python -m pip check

      - name: Full validation
        shell: pwsh
        run: |
          python run_full_validation.py

      - name: SEC-076+ security tail
        shell: pwsh
        run: |
          python security_tail_runner.py
'''
WORKFLOW.write_text(workflow, encoding="utf-8", newline="\n")

doctor = DOCTOR.read_text(encoding="utf-8")
anchor = '    checks["chain_identity"]={\n'
insert = '''    cffi_import,cffi_detail=check_module("cffi")
    cffi_version=None
    if cffi_import:
        try:cffi_version=importlib.metadata.version("cffi")
        except Exception as e:cffi_detail=f"metadata error: {e}"
    cffi_ok=cffi_import and cffi_version=="2.1.1"
    checks["cffi"]={
        "ok":cffi_ok,"import_ok":cffi_import,"version":cffi_version,
        "required":"2.1.1","detail":cffi_detail if not cffi_ok else "ok"
    }

    parser_import,parser_detail=check_module("pycparser")
    parser_version=None
    if parser_import:
        try:parser_version=importlib.metadata.version("pycparser")
        except Exception as e:parser_detail=f"metadata error: {e}"
    parser_ok=parser_import and parser_version=="3.0"
    checks["pycparser"]={
        "ok":parser_ok,"import_ok":parser_import,"version":parser_version,
        "required":"3.0","detail":parser_detail if not parser_ok else "ok"
    }

'''
if 'checks["cffi"]' not in doctor:
    if anchor not in doctor:
        raise SystemExit("doctor anchor missing")
    doctor = doctor.replace(anchor, insert + anchor, 1)
DOCTOR.write_text(doctor, encoding="utf-8", newline="\n")

sec170 = SEC170.read_text(encoding="utf-8")
old170 = '''    green(
        "runtime dependency security pins remain unchanged",
        pyproject["project"]["dependencies"]
        == ["cryptography==50.0.1","dilithium-py==1.4.0"],
    )
'''
new170 = '''    runtime_dependencies=pyproject["project"]["dependencies"]
    green(
        "runtime dependency security pins remain unchanged",
        "cryptography==50.0.1" in runtime_dependencies
        and "dilithium-py==1.4.0" in runtime_dependencies,
    )
'''
if old170 not in sec170:
    raise SystemExit("SEC-170 anchor missing")
sec170 = sec170.replace(old170, new170, 1)
SEC170.write_text(sec170, encoding="utf-8", newline="\n")

sec172 = '''#!/usr/bin/env python3
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
'''
SEC172.write_text(sec172, encoding="utf-8", newline="\n")

sec178 = '''#!/usr/bin/env python3
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
'''
SEC178.write_text(sec178, encoding="utf-8", newline="\n")

manifest=json.loads(MANIFEST.read_text(encoding="utf-8"))
for path in (
    WORKFLOW,
    REQ,
    PYPROJECT,
    DOCTOR,
    SEC170,
    SEC172,
    SEC178,
):
    raw=path.read_bytes()
    rel=path.as_posix()
    if rel.startswith("./"):
        rel=rel[2:]
    manifest["files"][rel]={
        "bytes":len(raw),
        "sha256":hashlib.sha256(raw).hexdigest(),
    }
MANIFEST.write_text(
    json.dumps(manifest, indent=2, ensure_ascii=False)+"\n",
    encoding="utf-8",
    newline="\n",
)

SELF.unlink()
