#!/usr/bin/env python3
"""Axven CLI JSON-RPC client — canonical UX."""
from __future__ import annotations
import argparse, json, sys, urllib.request, urllib.error

def call(host,port,method,params=None):
    raw=json.dumps({"method":method,"params":params or {}}).encode()
    req=urllib.request.Request(f"http://{host}:{port}/",data=raw,
        headers={"Content-Type":"application/json"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:return json.loads(e.read())
        except Exception:return {"ok":False,"error":f"HTTP {e.code}"}
    except urllib.error.URLError as e:
        return {"ok":False,"error":f"Node unavailable at {host}:{port}: {e.reason}"}
    except TimeoutError:
        return {"ok":False,"error":f"Node timeout at {host}:{port}"}

def main():
    ap=argparse.ArgumentParser(prog="axven-cli")
    ap.add_argument("--rpc-host",default="127.0.0.1")
    ap.add_argument("--rpc-port",type=int,default=18443)
    sp=ap.add_subparsers(dest="cmd",required=True)
    sp.add_parser("status"); sp.add_parser("overview"); sp.add_parser("addresses"); sp.add_parser("stop")
    b=sp.add_parser("balance"); b.add_argument("--scheme")
    u=sp.add_parser("list-unspent"); u.add_argument("scheme")
    m=sp.add_parser("mine"); m.add_argument("count",type=int,nargs="?",default=1); m.add_argument("--scheme")
    snd=sp.add_parser("send"); snd.add_argument("input_scheme"); snd.add_argument("recipient"); snd.add_argument("amount",type=int); snd.add_argument("fee",type=int)
    sync=sp.add_parser("sync-peer"); sync.add_argument("host"); sync.add_argument("port",type=int); sync.add_argument("--batch",type=int,default=128)
    a=ap.parse_args()
    mp={
      "status":("get_status",{}),"overview":("get_overview",{}),"addresses":("get_addresses",{}),"stop":("stop",{}),
      "balance":("get_balance",{"scheme":getattr(a,"scheme",None)}),
      "list-unspent":("list_unspent",{"scheme":getattr(a,"scheme",None)}),
      "mine":("mine",{"count":getattr(a,"count",1),"scheme":getattr(a,"scheme",None)}),
      "send":("send",{"input_scheme":getattr(a,"input_scheme",None),"recipient":getattr(a,"recipient",None),"amount":getattr(a,"amount",None),"fee":getattr(a,"fee",None)}),
      "sync-peer":("sync_peer",{"host":getattr(a,"host",None),"port":getattr(a,"port",None),"batch":getattr(a,"batch",128)}),
    }
    method,params=mp[a.cmd]
    out=call(a.rpc_host,a.rpc_port,method,params)
    print(json.dumps(out,indent=2,sort_keys=True))
    raise SystemExit(0 if out.get("ok") else 2)

if __name__=="__main__":main()
