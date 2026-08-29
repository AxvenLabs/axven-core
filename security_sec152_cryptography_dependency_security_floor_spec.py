#!/usr/bin/env python3
"""SEC-152 cryptography dependency security-floor contract."""

import importlib.metadata
from pathlib import Path
import tomllib
import axven
import doctor

EXPECTED="50.0.1"


def main():
    checks=0

    req_lines=[
        line.strip() for line in Path("requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    crypto_req=[line for line in req_lines if line.lower().startswith("cryptography")]
    assert crypto_req==[f"cryptography=={EXPECTED}"],crypto_req
    checks+=1
    print("[GREEN] requirements cryptography release is exactly pinned")

    project=tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    deps=project["project"]["dependencies"]
    crypto_deps=[dep for dep in deps if dep.lower().startswith("cryptography")]
    assert crypto_deps==[f"cryptography=={EXPECTED}"],crypto_deps
    checks+=1
    print("[GREEN] package metadata cryptography release is exactly pinned")

    installed=importlib.metadata.version("cryptography")
    assert installed==EXPECTED,(installed,EXPECTED)
    checks+=1
    print("[GREEN] installed cryptography matches security pin")

    result=doctor.run()
    crypto=result["checks"]["cryptography"]
    assert crypto["ok"] is True,crypto
    assert crypto["version"]==EXPECTED,crypto
    assert crypto["required"]==EXPECTED,crypto
    checks+=1
    print("[GREEN] doctor enforces the canonical cryptography release")

    real_version=doctor.importlib.metadata.version
    def fake_version(name):
        if name=="cryptography":
            return "50.0.0"
        return real_version(name)
    doctor.importlib.metadata.version=fake_version
    try:
        stale=doctor.run()["checks"]["cryptography"]
    finally:
        doctor.importlib.metadata.version=real_version
    assert stale["ok"] is False,stale
    assert stale["version"]=="50.0.0",stale
    checks+=1
    print("[GREEN] doctor fails closed on non-canonical cryptography release")

    assert "dilithium-py==1.4.0" in req_lines
    assert "dilithium-py==1.4.0" in deps
    checks+=1
    print("[GREEN] existing ML-DSA dependency pin unchanged")

    assert axven.CHAIN_ID=="axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks+=1
    print("[GREEN] canonical chain identity unchanged")

    assert checks==7,checks
    print("SEC-152 cryptography dependency security floor: 7/7 GREEN")


if __name__=="__main__":
    main()
