#!/usr/bin/env python3
"""SEC-188: isolate educational ML-DSA implementation to explicit legacy recovery."""
from __future__ import annotations
import builtins, tomllib
from pathlib import Path
from unittest import mock
import axven, doctor

def main():
    checks=[]
    def green(name,condition):
        assert condition,name; checks.append(name); print(f"[GREEN] {name}")
    pyproject=tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    runtime=pyproject["project"]["dependencies"]
    recovery=pyproject["project"]["optional-dependencies"]["legacy-mldsa-recovery"]
    requirements=Path("requirements.txt").read_text(encoding="utf-8").splitlines()
    workflow=Path(".github/workflows/validation.yml").read_text(encoding="utf-8")
    green("educational ML-DSA backend absent from default package dependencies","dilithium-py==1.4.0" not in runtime)
    green("educational ML-DSA backend absent from default requirements","dilithium-py==1.4.0" not in requirements)
    green("legacy recovery extra pins the educational backend exactly",recovery==["dilithium-py==1.4.0"])
    green("validation explicitly opts into legacy recovery coverage",'.[legacy-mldsa-recovery]' in workflow)
    real_check=doctor.check_module
    def absent(name):
        if name=="dilithium_py": return False,"ModuleNotFoundError: simulated absent optional backend"
        return real_check(name)
    with mock.patch.object(doctor,"check_module",side_effect=absent):
        status=doctor.run()
    green("doctor remains healthy when optional legacy backend is absent",status["ok"] is True and status["checks"]["legacy_mldsa_recovery"]["available"] is False)
    fresh=axven.MLDSAWallet(); msg=b"sec188-production-path"; sig=fresh.sign(msg)
    green("new wallet generation and signing remain pyca-only",len(fresh._secret)==32 and axven._verify_mldsa44_signature(fresh.public_key,msg,sig))
    saved=axven._ML; axven._ML=None
    real_import=builtins.__import__
    def blocked(name,*args,**kwargs):
        if name.startswith("dilithium_py"): raise ImportError("simulated absent recovery backend")
        return real_import(name,*args,**kwargs)
    try:
        with mock.patch("builtins.__import__",side_effect=blocked):
            try: axven._mldsa()
            except RuntimeError as exc: err=str(exc)
            else: raise AssertionError("legacy backend absence did not fail closed")
    finally:
        axven._ML=saved
    green("legacy recovery fails closed with explicit install guidance","legacy-mldsa-recovery" in err)
    green("canonical chain and PQ activation identity unchanged",axven.CHAIN_ID=="axven-devnet-2" and axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae" and axven.CHAIN_CONFIG["pq_scheme"]=="ml-dsa-44" and axven.CHAIN_CONFIG["pq_hybrid_activation_height"]==2000 and axven.CHAIN_CONFIG["pq_pure_activation_height"]==5000)
    print(f"SEC-188 legacy ML-DSA recovery isolation: {len(checks)}/{len(checks)} GREEN")
if __name__=="__main__": main()
