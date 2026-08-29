#!/usr/bin/env python3
"""SEC-165 production-daemon RPC bearer authentication contract."""
import json,os,socket,tempfile,urllib.error,urllib.request
from pathlib import Path
import axven
from core import AxvenCore
from datadir import DataDir
from rpc import RPCServer
import axven_cli,axven_core,canonical_ops

def post(addr,token=None,body=None):
    raw=body or json.dumps({"method":"get_status","params":{}}).encode()
    headers={"Content-Type":"application/json"}
    if token is not None: headers["Authorization"]="Bearer "+token
    req=urllib.request.Request(f"http://{addr[0]}:{addr[1]}/",data=raw,headers=headers,method="POST")
    try:
        with urllib.request.urlopen(req,timeout=3) as r:return r.status,json.loads(r.read())
    except urllib.error.HTTPError as e:return e.code,json.loads(e.read())

def main():
    checks=[]
    def green(name,cond): assert cond,name; checks.append(name); print(f"[GREEN] {name}")
    with tempfile.TemporaryDirectory(prefix="axven_sec165_") as td:
        dd=DataDir(td)
        token=dd.load_or_create_rpc_token()
        green("daemon RPC token is 256-bit lowercase hex",len(token)==64 and all(c in "0123456789abcdef" for c in token))
        green("RPC token persists exactly per datadir",dd.load_rpc_token()==token and dd.load_or_create_rpc_token()==token)
        green("RPC token file bytes are platform-canonical",dd.rpc_token_file.read_bytes()==token.encode("ascii")+b"\n" and len(dd.rpc_token_file.read_bytes())==65)
        if os.name=="posix": green("RPC token file is owner-only on POSIX",(dd.rpc_token_file.stat().st_mode & 0o777)==0o600)
        original=dd.rpc_token_file.read_bytes()
        dd.rpc_token_file.write_bytes(b"bad\n")
        try: dd.load_rpc_token()
        except ValueError: malformed=True
        else: malformed=False
        green("malformed persisted RPC token fails closed",malformed)
        dd.rpc_token_file.write_bytes(original)

        core=AxvenCore()
        server=RPCServer(core,"127.0.0.1",0,auth_token=token).start()
        try:
            status,body=post(server.address)
            green("missing bearer token is rejected",status==400 and body.get("ok") is False and "authorization" in body.get("error","").lower())
            status,body=post(server.address,"0"*64)
            green("incorrect bearer token is rejected",status==400 and body.get("ok") is False)
            status,body=post(server.address,token)
            green("correct bearer token reaches RPC dispatcher",status==200 and body.get("ok") is True and body["result"]["chain_id"]==axven.CHAIN_ID)
            # Auth is checked before framing/body parsing: unauthenticated malformed JSON never reaches parser work.
            status,body=post(server.address,body=b"{")
            green("authorization gate precedes request body parsing",status==400 and "authorization" in body.get("error","").lower())
        finally: server.stop()

        # Explicit test/library mode remains available only when caller deliberately omits a token.
        legacy=RPCServer(AxvenCore(),"127.0.0.1",0).start()
        try:
            status,body=post(legacy.address)
            green("explicit tokenless RPCServer test mode remains compatible",status==200 and body.get("ok") is True)
        finally: legacy.stop()

        green("CLI resolves the canonical datadir token",axven_cli.resolve_rpc_auth_token(td)==token)
        dd.rpc_token_file.write_bytes(b"a"*66)
        try: axven_cli.resolve_rpc_auth_token(td)
        except axven_cli.RPCClientError: oversized_cli_token=True
        else: oversized_cli_token=False
        green("CLI bounds RPC token-file reads before token parsing",oversized_cli_token)
        dd.rpc_token_file.write_bytes(original)
        env_old=os.environ.get("AXVEN_RPC_TOKEN")
        try:
            os.environ["AXVEN_RPC_TOKEN"]="1"*64
            green("explicit RPC token environment override is canonical",axven_cli.resolve_rpc_auth_token(td)=="1"*64)
        finally:
            if env_old is None: os.environ.pop("AXVEN_RPC_TOKEN",None)
            else: os.environ["AXVEN_RPC_TOKEN"]=env_old

    import inspect
    daemon_src=inspect.getsource(axven_core.main)
    green("production daemon always loads and passes RPC bearer token","load_or_create_rpc_token()" in daemon_src and "auth_token=rpc_token" in daemon_src)
    cli_src=inspect.getsource(axven_cli.call)
    green("CLI emits bearer authorization when token is available","Authorization" in cli_src and "Bearer " in cli_src)
    ops_src=inspect.getsource(canonical_ops.rpc)
    green("canonical operator helper emits bearer authorization","Authorization" in ops_src and "Bearer " in ops_src)
    green("SEC-165 leaves canonical chain identity unchanged",axven.CHAIN_ID=="axven-devnet-2" and axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
    print(f"SEC-165 daemon RPC bearer auth: {len(checks)}/{len(checks)} GREEN")
if __name__=='__main__': main()
