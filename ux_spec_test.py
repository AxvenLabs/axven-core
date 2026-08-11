#!/usr/bin/env python3
import io, json, subprocess, sys
from contextlib import redirect_stdout
import axven, wallet
from core import AxvenCore
from rpc import RPCServer
from axven_cli import call

def main():
    c=[]
    def ok(n,x): assert x,n; c.append(n)
    ed=axven.Wallet()
    ident=wallet.WalletIdentity(
        ed_keypair=(ed.public_key,ed.private_key),
        ml_keypair=(b"\x81"*1312,b"\x82"*2560)
    )
    core=AxvenCore(identity=ident)
    ov=core.overview()
    ok("overview chain",ov["chain_id"]==axven.CHAIN_ID)
    ok("overview addresses",ov["addresses"]["N"]==ident.address_n)
    ok("overview balances",set(ov["balances"])=={axven.SCHEME_ED25519,axven.SCHEME_ML_DSA,axven.SCHEME_HYBRID})
    ok("overview genesis",ov["genesis_hash"]==axven._genesis().hash())

    srv=RPCServer(core,port=0).start()
    try:
        port=srv.address[1]
        r=call("127.0.0.1",port,"get_overview")
        ok("rpc overview",r["ok"] and r["result"]["addresses"]["M"]==ident.address_m)
        r=call("127.0.0.1",port,"get_addresses")
        ok("rpc addresses",r["ok"] and r["result"]["H"]==ident.address_h)
        r=call("127.0.0.1",port,"get_balance",{"scheme":axven.SCHEME_ED25519})
        ok("rpc balance",r["ok"] and r["result"]==0)

        p=subprocess.run([sys.executable,"axven_cli.py","--rpc-port",str(port),"overview"],
                         cwd=".",text=True,capture_output=True,timeout=10)
        out=json.loads(p.stdout)
        ok("cli overview exit",p.returncode==0)
        ok("cli overview content",out["ok"] and out["result"]["chain_id"]==axven.CHAIN_ID)
    finally:
        srv.stop()

    # Friendly unavailable-node error (use an intentionally unreachable local port).
    r=call("127.0.0.1",1,"get_status")
    ok("offline node fails clean",not r["ok"])
    ok("offline node friendly",str(r["error"]).startswith("Node unavailable"))

    for name in [
      "setup.cmd","start-node1.cmd","start-node2.cmd","axven-console.cmd",
      "axven-console-node2.cmd","status-node1.cmd","status-node2.cmd",
      "sync-node2-from-node1.cmd","stop-node1.cmd","stop-node2.cmd"
    ]:
        ok("launcher "+name,__import__("pathlib").Path(name).is_file())

    print(f"UX spec: {len(c)}/{len(c)} GREEN")

if __name__=="__main__":main()
