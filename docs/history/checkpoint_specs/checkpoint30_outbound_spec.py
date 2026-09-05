#!/usr/bin/env python3
import socket
import axven, wallet
from core import AxvenCore
from p2p import NodeServer

c=[]
def ok(n,x): assert x,n; c.append(n)

def ident(fill):
    w=axven.Wallet()
    return wallet.WalletIdentity(ed_keypair=(w.public_key,w.private_key),
                                 ml_keypair=(bytes([fill])*1312,bytes([fill+1])*2560))

def main():
    remote=AxvenCore(identity=ident(31))
    server=NodeServer(remote.chain,remote.mempool,host="127.0.0.1",port=0).start()
    try:
        local=AxvenCore(identity=ident(41))
        local.add_outbound_peer(server.address)
        ok("peer registered",len(local.outbound_peers)==1)

        # Remote gets ahead; local pulls it.
        remote.mine(3)
        r=local.sync_outbound_peers()
        ok("initial outbound sync",r[0]["ok"] and local.chain.tip.height==3)
        ok("tip converged",local.chain.tip.hash()==remote.chain.tip.hash())

        # Local mines and proactively pushes the block to the remote peer.
        local.mine(1)
        ok("mined block propagated",remote.chain.tip.height==4)
        ok("propagated tip exact",remote.chain.tip.hash()==local.chain.tip.hash())

        # Remote gets ahead again; periodic-style pull recovers local.
        remote.mine(1)
        ok("remote advanced",remote.chain.tip.height==5)
        local.sync_outbound_peers()
        ok("resync converged",local.chain.tip.height==5)
        ok("final tip exact",remote.chain.tip.hash()==local.chain.tip.hash())

        # Failure is recorded, not fatal.
        local.add_outbound_peer(("127.0.0.1",1))
        rr=local.sync_outbound_peers()
        ok("failed peer nonfatal",any(not x["ok"] for x in rr))
        ok("peer error visible",any(x["last_error"] for x in local.outbound_peer_status()))

        # parser hardening
        try:
            local.add_outbound_peer("bad")
            raise AssertionError("bad peer accepted")
        except ValueError:
            c.append("bad peer rejected")
    finally:
        server.stop()
    print(f"Checkpoint 30 outbound spec: {len(c)}/{len(c)} GREEN")

if __name__=="__main__":main()
