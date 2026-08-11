#!/usr/bin/env python3
import copy, socket, threading
import axven, p2p

def main():
    checks=[]
    def ok(name,cond): assert cond,name; checks.append(name)

    ident=p2p.local_identity()
    ok("identity chain",ident["chain_id"]==axven.CHAIN_ID)
    ok("identity fingerprint",ident["config_fingerprint"]==axven.CONFIG_FINGERPRINT)
    ok("identity genesis",ident["genesis_hash"]==axven._genesis().hash())

    good={"type":"hello",**ident}; p2p.validate_handshake(good); ok("good handshake",True)
    for key in ("chain_id","config_fingerprint","genesis_hash","protocol_version"):
        bad=dict(good); bad[key]="bad" if key!="protocol_version" else 999
        try:p2p.validate_handshake(bad); raise AssertionError(key)
        except p2p.ProtocolError:checks.append("reject "+key)

    # Real socket framing + simultaneous handshake.
    a,b=socket.socketpair()
    got=[]
    th=threading.Thread(target=lambda: got.append(p2p.handshake(a))); th.start()
    peer=p2p.handshake(b); th.join(2); a.close(); b.close()
    ok("socket handshake both sides",len(got)==1 and peer["chain_id"]==axven.CHAIN_ID)

    w=axven.Wallet(); source=axven.Blockchain()
    for _ in range(axven.COINBASE_MATURITY+3): source.mine(w.address)
    ok("source validates",source.validate())

    # Locator sync from genesis into a fresh node.
    target=axven.Blockchain(); sess_src=p2p.PeerSession(source); sess_dst=p2p.PeerSession(target)
    reply=sess_src.handle({"type":"get_blocks","locator":sess_dst.locator(),"limit":128})
    res=sess_dst.handle(reply)
    ok("block sync count",res["count"]==source.tip.height)
    ok("sync tip exact",target.tip.hash()==source.tip.hash())
    ok("sync utxo exact",target.utxo==source.utxo)
    ok("sync validates",target.validate())

    # Tx propagation into a real mempool.
    mp=axven.Mempool(target)
    txid,idx,amount=target.spendable(w.address)[0]
    tx=axven.Transaction([axven.TxInput(txid,idx)],[axven.TxOutput(amount-1000,w.address)])
    signed=axven.Transaction([w.sign_input(tx,0)],tx.outputs)
    ack=p2p.PeerSession(target,mp).handle({"type":"tx","tx":signed.to_dict()})
    ok("tx propagated",ack["id"]==signed.txid() and signed.txid() in mp.txs)

    # Mine at source from equivalent state then propagate block.
    mp2=axven.Mempool(source); mp2.add(signed); blk=source.mine(w.address,mp2)
    ack=p2p.PeerSession(target,mp).handle({"type":"block","block":blk.to_dict()})
    ok("block propagated",ack["status"]=="extended")
    ok("post-block tips exact",target.tip.hash()==source.tip.hash())
    ok("confirmed tx removed",signed.txid() not in mp.txs)
    ok("post-block validates",target.validate())

    # Hostile block must reject cleanly, not crash.
    bad=source.build_candidate(w.address); bad.utxo_state_root="00"*32; bad.nonce=0
    while not bad.pow_ok(): bad.nonce+=1
    try:
        p2p.PeerSession(target,mp).handle({"type":"block","block":bad.to_dict()})
        raise AssertionError("hostile accepted")
    except p2p.ProtocolError: checks.append("hostile block clean reject")

    print(f"P2P spec: {len(checks)}/{len(checks)} GREEN")

if __name__=="__main__": main()
