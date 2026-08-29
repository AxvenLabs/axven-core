#!/usr/bin/env python3
"""Axven CLI JSON-RPC client — canonical UX."""
from __future__ import annotations
import argparse, json, os, sys, urllib.request, urllib.error
from pathlib import Path

MAX_RPC_RESPONSE_BYTES=16*1024*1024
MAX_RPC_TOKEN_FILE_BYTES=65

class RPCClientError(ValueError): pass


def _validate_rpc_auth_token(token):
    if type(token) is not str or len(token)!=64:
        raise RPCClientError("invalid RPC auth token")
    if any(ch not in "0123456789abcdef" for ch in token):
        raise RPCClientError("invalid RPC auth token")
    return token

def resolve_rpc_auth_token(datadir=None):
    env=os.environ.get("AXVEN_RPC_TOKEN")
    if env is not None:
        return _validate_rpc_auth_token(env)
    root=Path(datadir or os.environ.get("AXVEN_DATADIR","./axven-data")).expanduser()
    path=root/"rpc.token"
    if not path.exists():
        return None
    with open(path,"rb") as f:
        raw=f.read(MAX_RPC_TOKEN_FILE_BYTES+1)
    if len(raw)>MAX_RPC_TOKEN_FILE_BYTES:
        raise RPCClientError("invalid RPC auth token")
    if raw.endswith(b"\n"):
        raw=raw[:-1]
    try:
        token=raw.decode("ascii")
    except UnicodeError as exc:
        raise RPCClientError("invalid RPC auth token") from exc
    return _validate_rpc_auth_token(token)

def read_rpc_json_response(stream):
    raw=stream.read(MAX_RPC_RESPONSE_BYTES+1)
    if len(raw)>MAX_RPC_RESPONSE_BYTES:
        raise RPCClientError("RPC response too large")
    try:
        data=json.loads(raw)
    except (UnicodeError,json.JSONDecodeError,RecursionError) as exc:
        raise RPCClientError("invalid RPC response") from exc
    if type(data) is not dict:
        raise RPCClientError("RPC response must be object")
    return data

def call(host,port,method,params=None,auth_token=None):
    raw=json.dumps({"method":method,"params":params or {}}).encode()
    headers={"Content-Type":"application/json"}
    if auth_token is not None:
        headers["Authorization"]="Bearer "+_validate_rpc_auth_token(auth_token)
    req=urllib.request.Request(
        f"http://{host}:{port}/",data=raw,headers=headers,method="POST"
    )
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            try:return read_rpc_json_response(r)
            except RPCClientError as e:return {"ok":False,"error":str(e)}
    except urllib.error.HTTPError as e:
        try:return read_rpc_json_response(e)
        except RPCClientError as exc:return {"ok":False,"error":str(exc)}
    except urllib.error.URLError as e:
        return {"ok":False,"error":f"Node unavailable at {host}:{port}: {e.reason}"}
    except TimeoutError:
        return {"ok":False,"error":f"Node timeout at {host}:{port}"}

def main():
    ap=argparse.ArgumentParser(prog="axven-cli")
    ap.add_argument("--rpc-host",default="127.0.0.1")
    ap.add_argument("--rpc-port",type=int,default=18443)
    ap.add_argument("--datadir",default=os.environ.get("AXVEN_DATADIR","./axven-data"))
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
    out=call(
        a.rpc_host,a.rpc_port,method,params,
        auth_token=resolve_rpc_auth_token(a.datadir),
    )
    print(json.dumps(out,indent=2,sort_keys=True))
    raise SystemExit(0 if out.get("ok") else 2)

if __name__=="__main__":main()
