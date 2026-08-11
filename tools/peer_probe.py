#!/usr/bin/env python3
"""Read-only Axven P2P identity/status probe.

Use this from a second machine to prove that a publicly reachable P2P endpoint
is speaking the canonical Axven devnet protocol. It does not mutate the remote
node or local chain.
"""
from __future__ import annotations
import argparse, json
import p2p

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("port",type=int)
    ap.add_argument("--timeout",type=float,default=5.0)
    a=ap.parse_args()

    sock=p2p.connect((a.host,a.port),timeout=a.timeout)
    try:
        status=p2p.request(sock,{"type":"get_status"})
    finally:
        sock.close()

    out={
        "ok": True,
        "peer": f"{a.host}:{a.port}",
        "identity": p2p.local_identity(),
        "status": status,
    }
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=="__main__":
    main()
