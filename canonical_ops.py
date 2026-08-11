#!/usr/bin/env python3
"""Canonical devnet-2 operator helper.

This file does not modify consensus. It orchestrates the already-activated
Axven Core using persistent datadirs and loopback RPC/P2P.
"""
from __future__ import annotations
import argparse, json, os, subprocess, sys, time, urllib.request, urllib.error
from pathlib import Path

ROOT=Path(__file__).resolve().parent

def rpc(port, method, params=None):
    raw=json.dumps({"method":method,"params":params or {}}).encode()
    req=urllib.request.Request(f"http://127.0.0.1:{port}/",data=raw,
        headers={"Content-Type":"application/json"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())

def main():
    ap=argparse.ArgumentParser(prog="canonical-ops")
    sp=ap.add_subparsers(dest="cmd",required=True)

    s=sp.add_parser("status")
    s.add_argument("--rpc-port",type=int,default=18443)

    m=sp.add_parser("mine")
    m.add_argument("count",type=int,nargs="?",default=1)
    m.add_argument("--rpc-port",type=int,default=18443)
    m.add_argument("--scheme",default="ed25519")

    sy=sp.add_parser("sync")
    sy.add_argument("host")
    sy.add_argument("port",type=int)
    sy.add_argument("--rpc-port",type=int,default=18443)

    st=sp.add_parser("stop")
    st.add_argument("--rpc-port",type=int,default=18443)

    a=ap.parse_args()
    if a.cmd=="status":
        out=rpc(a.rpc_port,"get_status")
    elif a.cmd=="mine":
        out=rpc(a.rpc_port,"mine",{"count":a.count,"scheme":a.scheme})
    elif a.cmd=="sync":
        out=rpc(a.rpc_port,"sync_peer",{"host":a.host,"port":a.port,"batch":128})
    elif a.cmd=="stop":
        out=rpc(a.rpc_port,"stop")
    print(json.dumps(out,indent=2,sort_keys=True))
    if not out.get("ok",False):
        raise SystemExit(2)

if __name__=="__main__":main()
