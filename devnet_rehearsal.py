#!/usr/bin/env python3
"""Checkpoint 15: two-node operational devnet rehearsal.

Runs two independent Axven chains/mempools/wallets with real TCP P2P servers.
No consensus parameters are changed.
"""
from __future__ import annotations
import json, tempfile, shutil
import axven, wallet, p2p
from datadir import DataDir

def check(name, cond, checks):
    if not cond: raise AssertionError(name)
    checks.append(name)
    print(f"[GREEN] {name}", flush=True)

def sync(dst_chain, dst_mp, src_server):
    return p2p.sync_to_peer(src_server.address, p2p.PeerSession(dst_chain,dst_mp))

def state_root(chain):
    # Authoritative consensus helper; Blockchain intentionally has no
    # duplicated `utxo_root` attribute.
    return axven.expected_state_root(chain.utxo, chain.tip.height)

def main():
    checks=[]
    root=tempfile.mkdtemp(prefix="axven_devnet_rehearsal_")
    a_dir=DataDir(root+"/nodeA"); b_dir=DataDir(root+"/nodeB")
    a_srv=b_srv=None
    try:
        A=wallet.WalletIdentity(); B=wallet.WalletIdentity()
        a=a_dir.load_core(); b=b_dir.load_core()
        a.identity=A; b.identity=B
        a_srv=p2p.NodeServer(a.chain,a.mempool,"127.0.0.1",0).start()
        b_srv=p2p.NodeServer(b.chain,b.mempool,"127.0.0.1",0).start()
        check("independent P2P endpoints", a_srv.address!=b_srv.address, checks)
        check("same genesis", a.chain.tip.hash()==b.chain.tip.hash(), checks)

        # Mine enough N blocks on A for a mature coinbase.
        a.mine(axven.COINBASE_MATURITY+2, axven.SCHEME_ED25519)
        check("node A mined mature chain", a.chain.tip.height==axven.COINBASE_MATURITY+2, checks)
        n=sync(b.chain,b.mempool,a_srv)
        check("node B initial TCP catch-up", n>0 and b.chain.tip.hash()==a.chain.tip.hash(), checks)
        check("initial UTXO convergence", state_root(b.chain)==state_root(a.chain), checks)

        # Wallet A pays wallet B over an ordinary N transaction.
        amount=max(1, axven.block_reward(1,0)//4); fee=1
        sent=a.send(axven.SCHEME_ED25519,B.address_n,amount,fee)
        tx=axven.Transaction.from_dict(sent["transaction"])
        reply=p2p.propagate_tx(b_srv.address,tx)
        check("wallet tx propagated over TCP", reply.get("type")=="accepted", checks)
        check("tx present in both mempools", sent["txid"] in a.mempool.txs and sent["txid"] in b.mempool.txs, checks)

        # A mines it, propagates the block to B.
        block=a.chain.mine(A.address_n,a.mempool)
        reply=p2p.propagate_block(b_srv.address,block)
        check("block propagated over TCP", reply.get("type")=="accepted", checks)
        check("post-tx tip convergence", b.chain.tip.hash()==a.chain.tip.hash(), checks)
        check("recipient balance converged", b.chain.balance(B.address_n)==a.chain.balance(B.address_n)>0, checks)
        check("post-tx chain validates", a.chain.validate() and b.chain.validate(), checks)

        # Persist/restart both independently.
        a_dir.save_chain(a.chain); b_dir.save_chain(b.chain)
        a_srv.stop(); b_srv.stop(); a_srv=b_srv=None
        a2=a_dir.load_core(); b2=b_dir.load_core()
        a2.identity=A; b2.identity=B
        check("node A restart/replay", a2.chain.validate() and a2.chain.tip.hash()==a.chain.tip.hash(), checks)
        check("node B restart/replay", b2.chain.validate() and b2.chain.tip.hash()==b.chain.tip.hash(), checks)
        a_srv=p2p.NodeServer(a2.chain,a2.mempool,"127.0.0.1",0).start()
        b_srv=p2p.NodeServer(b2.chain,b2.mempool,"127.0.0.1",0).start()

        # Create divergence: A mines 1, B mines 2. Then A syncs B and must reorg.
        a2.mine(1,axven.SCHEME_ED25519)
        b2.mine(2,axven.SCHEME_ED25519)
        check("independent fork created", a2.chain.tip.hash()!=b2.chain.tip.hash(), checks)
        accepted=sync(a2.chain,a2.mempool,b_srv)
        check("heavier peer fork synchronized", accepted>0, checks)
        check("fork-choice converged to B", a2.chain.tip.hash()==b2.chain.tip.hash(), checks)
        check("post-reorg UTXO convergence", state_root(a2.chain)==state_root(b2.chain), checks)
        check("post-reorg validation", a2.chain.validate() and b2.chain.validate(), checks)

        # Reconnect/sync in reverse should be a no-op and preserve exact state.
        accepted=sync(b2.chain,b2.mempool,a_srv)
        check("reverse reconnect stable", accepted==0, checks)
        check("final exact tip convergence", a2.chain.tip.hash()==b2.chain.tip.hash(), checks)
        check("final exact UTXO convergence", state_root(a2.chain)==state_root(b2.chain), checks)

        print(json.dumps({
            "ok":True,"checks":len(checks),
            "height":a2.chain.tip.height,
            "tip_hash":a2.chain.tip.hash(),
            "utxo_root":state_root(a2.chain),
            "chain_id":axven.CHAIN_ID,
            "fingerprint":axven.CONFIG_FINGERPRINT,
            "genesis_hash":axven._genesis().hash(),
        },indent=2,sort_keys=True))
    finally:
        if a_srv:
            try:a_srv.stop()
            except Exception:pass
        if b_srv:
            try:b_srv.stop()
            except Exception:pass
        shutil.rmtree(root,ignore_errors=True)

if __name__=="__main__": main()
