#!/usr/bin/env python3
"""Axven environment preflight / release doctor."""
from __future__ import annotations
import importlib, importlib.metadata, json, platform, sys

def check_module(name):
    try:
        importlib.import_module(name)
        return True,"ok"
    except Exception as e:
        return False,f"{type(e).__name__}: {e}"

def run():
    import axven
    checks={}
    checks["python"]={"ok":sys.version_info >= (3,10),
                      "value":platform.python_version(),"required":">=3.10"}

    ok,msg=check_module("cryptography")
    checks["cryptography"]={"ok":ok,"detail":msg}

    pq_import,pq_detail=check_module("dilithium_py")
    pq_version=None
    if pq_import:
        try:pq_version=importlib.metadata.version("dilithium-py")
        except Exception as e:pq_detail=f"metadata error: {e}"
    pq_ok=pq_import and pq_version=="1.4.0"
    checks["dilithium_py"]={
        "ok":pq_ok,"import_ok":pq_import,"version":pq_version,
        "required":"1.4.0","detail":pq_detail if not pq_ok else "ok"
    }

    checks["chain_identity"]={
        "ok":(
            axven.CHAIN_ID=="axven-devnet-2" and
            axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae" and
            axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
        ),
        "chain_id":axven.CHAIN_ID,
        "fingerprint":axven.CONFIG_FINGERPRINT,
        "genesis_hash":axven._genesis().hash(),
    }
    checks["consensus_params"]={
        "ok":(
            axven.CHAIN_CONFIG["pq_hybrid_activation_height"]==2000 and
            axven.CHAIN_CONFIG["pq_pure_activation_height"]==5000 and
            axven.CHAIN_CONFIG["smt_activation_height"]==10000 and
            axven.CHAIN_CONFIG["max_block_bytes"]==7*1024*1024
        ),
        "config":dict(axven.CHAIN_CONFIG),
    }
    return {"ok":all(v["ok"] for v in checks.values()),"checks":checks}

def main():
    result=run()
    print(json.dumps(result,indent=2,sort_keys=True))
    raise SystemExit(0 if result["ok"] else 2)

if __name__=="__main__":main()
