#!/usr/bin/env python3
import socket,time
import axven,p2p

def main():
    c=[]
    def ok(n,x): assert x,n; c.append(n)
    w=axven.Wallet()
    a=axven.Blockchain()
    for _ in range(axven.COINBASE_MATURITY+5):a.mine(w.address)
    sa=p2p.NodeServer(a,axven.Mempool(a)).start()
    try:
        b=axven.Blockchain(); mb=axven.Mempool(b); sb=p2p.PeerSession(b,mb)
        n=p2p.sync_to_peer(sa.address,sb,limit=7)
        ok("multi-round tcp sync",n==a.tip.height)
        ok("initial tips exact",b.tip.hash()==a.tip.hash())
        ok("initial state exact",b.utxo==a.utxo)
        ok("initial validate",b.validate())

        # Disconnect, source advances, reconnect/catch-up.
        for _ in range(11):a.mine(w.address)
        n=p2p.sync_to_peer(sa.address,sb,limit=3)
        ok("reconnect catchup count",n==11)
        ok("reconnect tip exact",b.tip.hash()==a.tip.hash())
        ok("reconnect state exact",b.utxo==a.utxo)

        # Real TCP tx propagation into server A.
        txid,idx,amt=a.spendable(w.address)[0]
        tx=axven.Transaction([axven.TxInput(txid,idx)],[axven.TxOutput(amt-1234,w.address)])
        stx=axven.Transaction([w.sign_input(tx,0)],tx.outputs)
        ack=p2p.propagate_tx(sa.address,stx)
        ok("tcp tx accepted",ack["id"]==stx.txid() and stx.txid() in sa.mempool.txs)

        # Mine it, then propagate resulting block to B over a real B server.
        blk=a.mine(w.address,sa.mempool)
        srvb=p2p.NodeServer(b,mb).start()
        try:
            ack=p2p.propagate_block(srvb.address,blk)
            ok("tcp block accepted",ack["status"]=="extended")
            ok("tcp block tips exact",b.tip.hash()==a.tip.hash())
            ok("tcp block state exact",b.utxo==a.utxo)
            ok("confirmed mempool clean",stx.txid() not in mb.txs)
        finally:srvb.stop()

        # Malformed frame must only kill that connection, not listener.
        bad=socket.create_connection(sa.address,timeout=2)
        bad.sendall((p2p.MAX_MESSAGE_BYTES+1).to_bytes(4,"big")); bad.close()
        time.sleep(.05)
        sock=p2p.connect(sa.address); status=p2p.request(sock,{"type":"get_status"}); sock.close()
        ok("listener survives malformed peer",status["tip_hash"]==a.tip.hash())

        # Wrong-network handshake rejected without poisoning listener.
        raw=socket.create_connection(sa.address,timeout=2)
        evil=p2p.hello_message(); evil["chain_id"]="wrong-chain"
        p2p.send_message(raw,evil)
        try:
            peer=p2p.recv_message(raw)
            # Server sends its hello first; validate it locally then connection should close.
            p2p.validate_handshake(peer)
            try:p2p.recv_message(raw); raise AssertionError("bad peer remained connected")
            except (EOFError,OSError,socket.timeout):pass
        finally:raw.close()
        sock=p2p.connect(sa.address); sock.close()
        ok("listener survives identity mismatch",True)
    finally:sa.stop()
    print(f"P2P TCP lifecycle: {len(c)}/{len(c)} GREEN")

if __name__=="__main__":main()
