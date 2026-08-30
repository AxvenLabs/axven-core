#!/usr/bin/env python3
"""Axven CLI JSON-RPC client — canonical UX."""
from __future__ import annotations
import argparse, json, os, stat, sys, urllib.request, urllib.error
from pathlib import Path

MAX_RPC_RESPONSE_BYTES=16*1024*1024
MAX_RPC_RESPONSE_JSON_NESTING_DEPTH=32
MAX_RPC_RESPONSE_JSON_STRUCTURAL_ITEMS=1024*1024
MAX_RPC_TOKEN_FILE_BYTES=65
_AUTHENTICATED_RPC_HOSTS={"127.0.0.1","localhost","::1"}

class RPCClientError(ValueError): pass

class _RejectRPCRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise RPCClientError("RPC redirects are not allowed")

def _build_rpc_opener():
    # Bearer-authenticated localhost traffic must never inherit ambient proxy
    # configuration or follow redirects that could forward Authorization.
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _RejectRPCRedirects(),
    )

def open_rpc_request(req,timeout):
    return _build_rpc_opener().open(req,timeout=timeout)

def _validate_rpc_auth_token(token):
    if type(token) is not str or len(token)!=64:
        raise RPCClientError("invalid RPC auth token")
    if any(ch not in "0123456789abcdef" for ch in token):
        raise RPCClientError("invalid RPC auth token")
    return token

def _read_secure_rpc_token_file(path):
    path=os.fspath(path)
    try:
        before=os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(before.st_mode):
        raise RPCClientError("unsafe RPC token file")
    flags=os.O_RDONLY
    if hasattr(os,"O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os,"O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd=None
    try:
        try:
            fd=os.open(path,flags)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise RPCClientError("unsafe RPC token file") from exc
        current=os.fstat(fd)
        if not stat.S_ISREG(current.st_mode):
            raise RPCClientError("unsafe RPC token file")
        if (before.st_dev,before.st_ino)!=(current.st_dev,current.st_ino):
            raise RPCClientError("RPC token file changed during open")
        if getattr(current,"st_nlink",1)!=1:
            raise RPCClientError("unsafe RPC token hardlink count")
        if os.name=="posix":
            if current.st_mode & 0o077:
                raise RPCClientError("RPC token file permissions must be owner-only")
            if hasattr(os,"getuid") and current.st_uid!=os.getuid():
                raise RPCClientError("RPC token file owner mismatch")
        with os.fdopen(fd,"rb") as f:
            fd=None
            raw=f.read(MAX_RPC_TOKEN_FILE_BYTES+1)
    finally:
        if fd is not None:
            os.close(fd)
    if len(raw)>MAX_RPC_TOKEN_FILE_BYTES:
        raise RPCClientError("invalid RPC auth token")
    return raw

def resolve_rpc_auth_token(datadir=None):
    env=os.environ.get("AXVEN_RPC_TOKEN")
    if env is not None:
        return _validate_rpc_auth_token(env)
    root=Path(datadir or os.environ.get("AXVEN_DATADIR","./axven-data")).expanduser()
    path=root/"rpc.token"
    raw=_read_secure_rpc_token_file(path)
    if raw is None:
        return None
    if raw.endswith(b"\n"):
        raw=raw[:-1]
    try:
        token=raw.decode("ascii")
    except UnicodeError as exc:
        raise RPCClientError("invalid RPC auth token") from exc
    return _validate_rpc_auth_token(token)

def _reject_duplicate_rpc_response_json_keys(pairs):
    obj={}
    for key,value in pairs:
        if key in obj:
            raise RPCClientError("duplicate RPC response JSON key")
        obj[key]=value
    return obj

def _preflight_rpc_response_json(
    raw,
    max_depth=None,
    max_items=None,
):
    """Bound response JSON nesting/fan-out before parser allocation."""
    if type(raw) is not bytes:
        raise RPCClientError("invalid RPC response")
    if max_depth is None:
        max_depth=MAX_RPC_RESPONSE_JSON_NESTING_DEPTH
    if max_items is None:
        max_items=MAX_RPC_RESPONSE_JSON_STRUCTURAL_ITEMS
    if type(max_depth) is not int or max_depth<1:
        raise RPCClientError("invalid RPC response JSON limit")
    if type(max_items) is not int or max_items<1:
        raise RPCClientError("invalid RPC response JSON limit")
    stack=[]
    structural_items=0
    in_string=False
    escaped=False
    for value in raw:
        if in_string:
            if escaped:
                escaped=False
            elif value==0x5C:
                escaped=True
            elif value==0x22:
                in_string=False
            continue
        if value==0x22:
            in_string=True
            continue
        if value in (0x7B,0x5B):
            structural_items+=1
            if structural_items>max_items:
                raise RPCClientError("RPC response JSON too complex")
            stack.append(value)
            if len(stack)>max_depth:
                raise RPCClientError("RPC response JSON nesting too deep")
            continue
        if value==0x2C and stack:
            structural_items+=1
            if structural_items>max_items:
                raise RPCClientError("RPC response JSON too complex")
            continue
        if value==0x7D:
            if stack and stack[-1]==0x7B:
                stack.pop()
            continue
        if value==0x5D:
            if stack and stack[-1]==0x5B:
                stack.pop()


def read_rpc_json_response(stream):
    raw=stream.read(MAX_RPC_RESPONSE_BYTES+1)
    if len(raw)>MAX_RPC_RESPONSE_BYTES:
        raise RPCClientError("RPC response too large")
    _preflight_rpc_response_json(raw)
    try:
        decoded=raw.decode("utf-8")
    except UnicodeError as exc:
        raise RPCClientError("invalid RPC response") from exc
    try:
        data=json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_rpc_response_json_keys,
        )
    except RPCClientError:
        raise
    except (ValueError,RecursionError) as exc:
        raise RPCClientError("invalid RPC response") from exc
    if type(data) is not dict:
        raise RPCClientError("RPC response must be object")
    return data

def _rpc_client_url(host,port,auth_token=None):
    if type(host) is not str or not host or len(host)>255:
        raise RPCClientError("invalid RPC host")
    if any(ch in host for ch in "/\\@ \t\r\n"):
        raise RPCClientError("invalid RPC host")
    if type(port) is not int or port<1 or port>65535:
        raise RPCClientError("invalid RPC port")
    if auth_token is not None and host not in _AUTHENTICATED_RPC_HOSTS:
        raise RPCClientError("authenticated RPC target must be loopback")
    authority=f"[{host}]" if ":" in host else host
    return f"http://{authority}:{port}/"

def call(host,port,method,params=None,auth_token=None):
    try:
        token=None if auth_token is None else _validate_rpc_auth_token(auth_token)
        url=_rpc_client_url(host,port,token)
    except RPCClientError as exc:
        return {"ok":False,"error":str(exc)}
    raw=json.dumps({"method":method,"params":params or {}}).encode()
    headers={"Content-Type":"application/json"}
    if token is not None:
        headers["Authorization"]="Bearer "+token
    req=urllib.request.Request(url,data=raw,headers=headers,method="POST")
    try:
        with open_rpc_request(req,timeout=10) as r:
            try:return read_rpc_json_response(r)
            except RPCClientError as e:return {"ok":False,"error":str(e)}
    except RPCClientError as e:
        return {"ok":False,"error":str(e)}
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
