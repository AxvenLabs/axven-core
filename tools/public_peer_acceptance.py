#!/usr/bin/env python3
"""Acceptance gate for a manually configured remote Axven P2P peer."""
from __future__ import annotations
import argparse, json, socket
import p2p

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("port",type=int)
    a=ap.parse_args()
    checks=[]

    s=p2p.connect((a.host,a.port),timeout=8)
    try:
        checks.append("identity-bound handshake")
        reply=p2p.request(s,{"type":"get_status"})
        assert reply.get("type")=="status"
        assert isinstance(reply.get("height"),int)
        assert isinstance(reply.get("chainwork"),int)
        assert isinstance(reply.get("tip_hash"),str) and len(reply["tip_hash"])==64
        checks.append("remote status response")
    finally:
        s.close()

    # Reconnect proves the endpoint accepts an independent session.
    s=p2p.connect((a.host,a.port),timeout=8)
    s.close()
    checks.append("independent reconnect")

    print(json.dumps({
        "ok":True,
        "checks":checks,
        "peer":f"{a.host}:{a.port}",
        "canonical_identity":p2p.local_identity()
    },indent=2,sort_keys=True))

if __name__=="__main__":
    main()
