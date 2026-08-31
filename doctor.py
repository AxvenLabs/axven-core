#!/usr/bin/env python3
"""Axven environment preflight / release doctor."""
from __future__ import annotations
import importlib, importlib.metadata, json, platform, re, sys

def check_module(name):
    try:
        importlib.import_module(name)
        return True,"ok"
    except Exception as e:
        return False,f"{type(e).__name__}: {e}"

PYTHON_MIN = (3, 13, 15)
PYTHON_MAX_EXCLUSIVE = (3, 14, 0)
PYTHON_REQUIRED = ">=3.13.15,<3.14"

# OpenSSL's 2026-08-25 security release fixed multiple issues, including
# CVE-2026-63072. Axven also requires an OpenSSL line with ML-DSA support.
OPENSSL_SECURITY_FLOORS = {
    (4, 0): (4, 0, 2),
    (3, 6): (3, 6, 4),
    (3, 5): (3, 5, 8),
}
OPENSSL_REQUIRED = (
    "OpenSSL >=4.0.2 on 4.0.x, >=3.6.4 on 3.6.x, "
    "or >=3.5.8 on 3.5.x"
)
_OPENSSL_VERSION_RE = re.compile(r"^OpenSSL (\d+)\.(\d+)\.(\d+)(?: [^\r\n]+)?$")


def _python_runtime_supported(version_info=None):
    if version_info is None:
        version_info = sys.version_info
    current = tuple(version_info[:3])
    return PYTHON_MIN <= current < PYTHON_MAX_EXCLUSIVE


def _openssl_backend_supported(version_text):
    if type(version_text) is not str:
        return False
    match = _OPENSSL_VERSION_RE.fullmatch(version_text)
    if not match:
        return False
    version = tuple(int(part) for part in match.groups())
    floor = OPENSSL_SECURITY_FLOORS.get(version[:2])
    return floor is not None and version >= floor


def _openssl_backend_version_text():
    from cryptography.hazmat.backends.openssl.backend import backend
    return backend.openssl_version_text()


def run():
    import axven
    checks={}
    checks["python"]={
        "ok":_python_runtime_supported(),
        "value":platform.python_version(),
        "required":PYTHON_REQUIRED,
    }

    crypto_import,crypto_detail=check_module("cryptography")
    crypto_version=None
    if crypto_import:
        try:crypto_version=importlib.metadata.version("cryptography")
        except Exception as e:crypto_detail=f"metadata error: {e}"
    crypto_ok=crypto_import and crypto_version=="50.0.1"
    checks["cryptography"]={
        "ok":crypto_ok,"import_ok":crypto_import,"version":crypto_version,
        "required":"50.0.1","detail":crypto_detail if not crypto_ok else "ok"
    }

    openssl_version=None
    openssl_detail="cryptography unavailable"
    openssl_ok=False
    if crypto_import:
        try:
            openssl_version=_openssl_backend_version_text()
            openssl_ok=_openssl_backend_supported(openssl_version)
            openssl_detail="ok" if openssl_ok else "unsupported or vulnerable OpenSSL backend"
        except Exception as e:
            openssl_detail=f"{type(e).__name__}: {e}"
    checks["openssl_backend"]={
        "ok":openssl_ok,
        "version":openssl_version,
        "required":OPENSSL_REQUIRED,
        "detail":openssl_detail,
    }

    pq_import,pq_detail=check_module("dilithium_py")
    pq_version=None
    if pq_import:
        try:pq_version=importlib.metadata.version("dilithium-py")
        except Exception as e:pq_detail=f"metadata error: {e}"
    pq_ok=(not pq_import) or pq_version=="1.4.0"
    checks["legacy_mldsa_recovery"]={
        "ok":pq_ok,"available":pq_import,"version":pq_version,
        "required":"optional:1.4.0",
        "detail":("not installed (optional)" if not pq_import else ("ok" if pq_ok else pq_detail)),
    }

    cffi_import,cffi_detail=check_module("cffi")
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
