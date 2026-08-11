#!/usr/bin/env python3
import json, urllib.request, urllib.error
import axven, wallet
from core import AxvenCore
from explorer import ExplorerServer

def get(addr,path):
    try:
        with urllib.request.urlopen(f"http://{addr[0]}:{addr[1]}{path}",timeout=5) as r:
            return r.status,r.headers.get("Content-Type"),r.read()
    except urllib.error.HTTPError as e:
        return e.code,e.headers.get("Content-Type"),e.read()

def main():
    c=[]
    def ok(n,x): assert x,n; c.append(n)

    ed=axven.Wallet()
    ident=wallet.WalletIdentity(ed_keypair=(ed.public_key,ed.private_key),
                                ml_keypair=(b"\x91"*1312,b"\x92"*2560))
    core=AxvenCore(identity=ident)
    core.mine(3,axven.SCHEME_ED25519)

    latest=core.recent_blocks(2)
    ok("recent blocks count",len(latest)==2)
    ok("recent newest first",latest[0]["height"]==3 and latest[1]["height"]==2)
    b=core.get_block(1)
    ok("block by height",b["height"]==1)
    ok("block hash",b["hash"]==core.chain.blocks[1].hash())
    cbid=b["transactions"][0]["txid"]
    tx=core.get_transaction(cbid)
    ok("confirmed tx lookup",tx["status"]=="confirmed" and tx["height"]==1)
    ok("mempool empty",core.mempool_view()["size"]==0)
    sm=core.explorer_summary()
    ok("summary height",sm["height"]==3)
    ok("summary state root",sm["state_root"]==axven.expected_state_root(core.chain.utxo,3))

    srv=ExplorerServer(core).start()
    try:
        st,ct,raw=get(srv.address,"/")
        ok("html page",st==200 and b"Axven Explorer" in raw)
        st,ct,raw=get(srv.address,"/api/summary")
        data=json.loads(raw); ok("summary api",st==200 and data["result"]["height"]==3)
        st,ct,raw=get(srv.address,"/api/blocks?limit=2")
        data=json.loads(raw); ok("blocks api",len(data["result"])==2)
        st,ct,raw=get(srv.address,"/api/block/1")
        data=json.loads(raw); ok("block api",data["result"]["height"]==1)
        st,ct,raw=get(srv.address,f"/api/tx/{cbid}")
        data=json.loads(raw); ok("tx api",data["result"]["txid"]==cbid)
        st,ct,raw=get(srv.address,"/api/mempool")
        data=json.loads(raw); ok("mempool api",data["result"]["size"]==0)
        st,ct,raw=get(srv.address,"/api/block/999999")
        ok("missing block 404",st==404)
    finally:srv.stop()

    try:
        ExplorerServer(core,host="0.0.0.0")
        raise AssertionError("public bind allowed")
    except ValueError:
        c.append("explorer loopback only")

    print(f"Explorer spec: {len(c)}/{len(c)} GREEN")

if __name__=="__main__":main()
