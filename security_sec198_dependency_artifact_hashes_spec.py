#!/usr/bin/env python3
"""SEC-198: validation dependencies must be exact, wheel-only, and hash locked."""
from __future__ import annotations

import importlib.metadata
import re
from pathlib import Path

import axven

TOOLCHAIN = {
    "pip": ("26.2.1", {"71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e"}),
    "setuptools": ("84.0.0", {"51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670"}),
    "wheel": ("0.48.0", {"3217dcc807155e45db462d7ef2431f5ddda0d7273b700d05a67b271ceb1287ab"}),
    "packaging": ("26.3", {"d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c"}),
}
RUNTIME = {
    "cryptography": (
        "50.0.1",
        {
            "aed8db4f6d71c51efb89530e12d9464e7bf2923d46c3205dc794a2a93f8c0648",
            "55d16b1ef3ee0958d893a977b19777887e546c9954ea81b200c3301a864013f2",
        },
    ),
    "cffi": ("2.1.1", {"1aa5645c30469b09530c4ebca77ebf8f17618293c58f8549cb1a543a50236e7d"}),
    "pycparser": ("3.0", {"b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992"}),
    "dilithium-py": ("1.4.0", {"dda3ae43e6e3d212ae1fe1b30d5b6dffe5e25a1f389d1fea26faad4afdc33ff8"}),
}


def _logical_lines(path):
    out=[]
    current=""
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line=raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            current += line[:-1].strip() + " "
            continue
        current += line
        out.append(current.strip())
        current=""
    if current:
        raise AssertionError(f"unterminated requirement continuation: {path}")
    return out


def _parse_lock(path):
    parsed={}
    for line in _logical_lines(path):
        match=re.match(r"^([A-Za-z0-9_.-]+)==([^ ]+)(?: +--hash=sha256:[0-9a-f]{64})+$",line)
        if not match:
            raise AssertionError(f"non-canonical lock entry: {line!r}")
        name,version=match.groups()
        hashes=set(re.findall(r"--hash=sha256:([0-9a-f]{64})",line))
        if name in parsed:
            raise AssertionError(f"duplicate lock entry: {name}")
        parsed[name]=(version,hashes)
    return parsed


def main():
    checks=[]
    def green(label, condition):
        assert condition,label
        checks.append(label)
        print("[GREEN]",label)

    toolchain=_parse_lock("requirements-ci-toolchain.lock")
    runtime=_parse_lock("requirements-ci-runtime-windows.lock")
    workflow=Path(".github/workflows/validation.yml").read_text(encoding="utf-8")

    green("packaging toolchain lock pins exact official artifact hashes",toolchain==TOOLCHAIN)
    green("runtime validation lock pins exact official artifact hashes",runtime==RUNTIME)
    green(
        "CI requires hashes and wheels for both external dependency phases",
        workflow.count("--require-hashes") == 2
        and workflow.count("--only-binary=:all:") == 2
        and workflow.count("--no-deps") >= 3,
    )
    green(
        "CI consumes only the dedicated toolchain and runtime lock files",
        "-r requirements-ci-toolchain.lock" in workflow
        and "-r requirements-ci-runtime-windows.lock" in workflow,
    )
    green(
        "editable Axven install cannot create an unpinned isolated build environment",
        'python -m pip install --no-build-isolation --no-deps -e ".[legacy-mldsa-recovery]"' in workflow,
    )
    green(
        "ambient version-only dependency installation is absent from validation CI",
        'pip install "pip==' not in workflow
        and 'pip install "cryptography==' not in workflow
        and "pip install --upgrade pip" not in workflow,
    )
    green(
        "active validation environment still matches every exact dependency version",
        all(importlib.metadata.version(name)==version for name,(version,_) in {**TOOLCHAIN,**RUNTIME}.items()),
    )
    green(
        "cryptography validation admits only the two compatible pinned Windows ABI3 artifacts",
        len(RUNTIME["cryptography"][1]) == 2
        and all(len(value)==64 for value in RUNTIME["cryptography"][1]),
    )
    green(
        "dependency artifact hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    assert len(checks)==9,len(checks)
    print("SEC-198 dependency artifact hashes: 9/9 GREEN")


if __name__ == "__main__":
    main()
