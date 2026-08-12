#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, time
import p2p

EXPECTED_CHAIN_ID="axven-devnet-2"
EXPECTED_FINGERPRINT="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
EXPECTED_GENESIS="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("host",nargs="?",default="seed.axven.org")
    ap.add_argument("port",nargs="?",type=int,default=18444)
    ap.add_argument("--timeout",type=float,default=5.0)
    ap.add_argument("--min-height",type=int,default=0)
    a=ap.parse_args()
    t0=time.time()
    sock=p2p.connect((a.host,a.port),timeout=a.timeout)
    try:
        status=p2p.request(sock,{"type":"get_status"})
    finally:
        sock.close()
    ident=p2p.local_identity()
    checks={
        "chain_id": ident.get("chain_id")==EXPECTED_CHAIN_ID,
        "fingerprint": ident.get("config_fingerprint")==EXPECTED_FINGERPRINT,
        "genesis": ident.get("genesis_hash")==EXPECTED_GENESIS,
        "protocol_version": ident.get("protocol_version")==1,
        "status_type": status.get("type")=="status",
        "height": isinstance(status.get("height"),int) and status["height"]>=a.min_height,
        "chainwork": isinstance(status.get("chainwork"),int) and status["chainwork"]>0,
        "tip_hash": isinstance(status.get("tip_hash"),str) and len(status["tip_hash"])==64,
    }
    out={"ok":all(checks.values()),"peer":f"{a.host}:{a.port}",
         "latency_ms":round((time.time()-t0)*1000,1),
         "identity":ident,"status":status,"checks":checks}
    print(json.dumps(out,indent=2,sort_keys=True))
    if not out["ok"]:
        raise SystemExit(2)

if __name__=="__main__":
    main()
