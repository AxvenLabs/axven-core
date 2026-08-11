#!/usr/bin/env python3
import json, urllib.request, urllib.error
import axven, wallet, p2p
from core import AxvenCore
from rpc import RPCServer

def call(addr, method, params=None):
    raw=json.dumps({"method":method,"params":params or {}}).encode()
    req=urllib.request.Request(f"http://{addr[0]}:{addr[1]}/",data=raw,
                               headers={"Content-Type":"application/json"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=4) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())

def main():
    c=[]
    def ok(n,x): assert x,n; c.append(n)

    ed=axven.Wallet()
    # Opaque ML material is intentionally unused in this Ed25519-only integration test.
    ident=wallet.WalletIdentity(
        ed_keypair=(ed.public_key,ed.private_key),
        ml_keypair=(b"\x42"*1312,b"\x24"*2560)
    )
    core=AxvenCore(identity=ident)
    st=core.status()
    ok("core identity",st["chain_id"]==axven.CHAIN_ID)
    ok("core genesis",st["genesis_hash"]==axven._genesis().hash())
    ok("wallet loaded",st["wallet_loaded"] is True)
    ok("addresses exposed",core.addresses()["N"]==ed.address)

    # Mine enough for an N coin to mature using real consensus.
    core.mine(axven.COINBASE_MATURITY+2,axven.SCHEME_ED25519)
    ok("core chain validates",core.chain.validate())
    bal=core.balance(axven.SCHEME_ED25519)
    ok("balance positive",bal>0)
    ok("utxo list nonempty",len(core.list_unspent(axven.SCHEME_ED25519))>0)

    # Wallet-native send -> real mempool -> mine confirmation.
    sent=core.send(axven.SCHEME_ED25519,ident.address_n,1000,100)
    tid=sent["txid"]
    ok("send enters mempool",tid in core.mempool.txs)
    ok("pending reservation",len(core.pending._reserved)>0)
    core.mine(1,axven.SCHEME_ED25519)
    ok("confirmed removed",tid not in core.mempool.txs)
    ok("pending reconciled",len(core.pending._reserved)==0)
    ok("post-send validates",core.chain.validate())

    # Local RPC.
    srv=RPCServer(core).start()
    try:
        r=call(srv.address,"get_status")
        ok("rpc status",r["ok"] and r["result"]["tip_hash"]==core.chain.tip.hash())
        r=call(srv.address,"get_chain_config")
        ok("rpc config",r["ok"] and r["result"]["chain_id"]==axven.CHAIN_ID)
        r=call(srv.address,"get_addresses")
        ok("rpc addresses",r["ok"] and r["result"]["N"]==ident.address_n)
        r=call(srv.address,"get_balance",{"scheme":axven.SCHEME_ED25519})
        ok("rpc balance",r["ok"] and r["result"]==core.balance(axven.SCHEME_ED25519))
        r=call(srv.address,"list_unspent",{"scheme":axven.SCHEME_ED25519})
        ok("rpc utxo",r["ok"] and isinstance(r["result"],list))
        r=call(srv.address,"unknown")
        ok("rpc unknown fails",not r["ok"])
    finally:srv.stop()

    # RPC cannot bind publicly in this checkpoint.
    try:
        RPCServer(core,host="0.0.0.0",port=0)
        raise AssertionError("public bind accepted")
    except ValueError:
        c.append("rpc loopback only")

    # Core P2P wrapper + remote sync.
    addr=core.start_p2p()
    try:
        other=AxvenCore()
        accepted=other.sync_peer(addr[0],addr[1],batch=9)
        ok("core p2p sync count",accepted==core.chain.tip.height)
        ok("core p2p tip",other.chain.tip.hash()==core.chain.tip.hash())
        ok("core p2p state",other.chain.utxo==core.chain.utxo)
        ok("core p2p validate",other.chain.validate())
    finally:core.stop_p2p()

    print(f"Core/RPC: {len(c)}/{len(c)} GREEN")

if __name__=="__main__":main()
