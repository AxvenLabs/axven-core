#!/usr/bin/env python3
import json, sys
def main():
    out={"ok":False}
    try:
        try:
            from dilithium_py.ml_dsa import ML_DSA_44
        except Exception:
            from dilithium_py.ml_dsa.default_parameters import ML_DSA_44
        pk,sk=ML_DSA_44.keygen()
        msg=b"axven-pq-dependency-check-v1"
        sig=ML_DSA_44.sign(sk,msg)
        valid=bool(ML_DSA_44.verify(pk,msg,sig))
        out={"ok":valid,"public_key_bytes":len(pk),"secret_key_bytes":len(sk),
             "signature_bytes":len(sig),"resign_differs":ML_DSA_44.sign(sk,msg)!=sig}
    except Exception as e:
        out={"ok":False,"error":f"{type(e).__name__}: {e}"}
    print(json.dumps(out,indent=2,sort_keys=True))
    raise SystemExit(0 if out["ok"] else 2)
if __name__=="__main__":main()
