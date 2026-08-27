#!/usr/bin/env python3
"""SEC-089 bounds outbound P2P handshake and response receive time."""
import socket, threading, time
import axven
import p2p

TRICKLE_INTERVAL=0.08
TEST_DEADLINE=0.28

def trickle_frame(sock,msg):
    raw=p2p._json_bytes(msg)
    frame=len(raw).to_bytes(4,"big")+raw
    try:
        for byte in frame:
            sock.sendall(bytes((byte,)))
            time.sleep(TRICKLE_INTERVAL)
    except OSError:
        pass

def main():
    checks=[]
    def ok(name,cond):
        assert cond,name
        checks.append(name); print(f"[GREEN] {name}")

    listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    listener.bind(("127.0.0.1",0)); listener.listen(1)
    accepted=[]
    def slow_hello():
        conn,_=listener.accept(); accepted.append(conn)
        trickle_frame(conn,p2p.hello_message())
    threading.Thread(target=slow_hello,daemon=True).start()
    started=time.monotonic()
    try:
        p2p.connect(listener.getsockname(),timeout=TEST_DEADLINE)
    except (p2p.ProtocolError,socket.timeout,OSError):
        elapsed=time.monotonic()-started
    else:
        raise AssertionError("outbound trickle handshake escaped absolute deadline")
    ok("outbound trickle handshake bounded",elapsed<0.80)
    listener.close()
    for conn in accepted:
        try:conn.close()
        except OSError:pass

    left,right=socket.socketpair()
    try:
        left.settimeout(1.0)
        p2p.OUTBOUND_MESSAGE_DEADLINE=TEST_DEADLINE
        threading.Thread(
            target=trickle_frame,
            args=(right,{"type":"status","height":0}),
            daemon=True,
        ).start()
        started=time.monotonic()
        try:
            p2p.request(left,{"type":"get_status"})
        except (p2p.ProtocolError,socket.timeout,OSError):
            elapsed=time.monotonic()-started
        else:
            raise AssertionError("outbound trickle response escaped absolute deadline")
        ok("outbound trickle response bounded",elapsed<0.80)
        ok("request restores caller socket timeout",left.gettimeout()==1.0)
    finally:
        left.close(); right.close()

    chain=axven.Blockchain(); mempool=axven.Mempool(chain)
    server=p2p.NodeServer(chain,mempool).start()
    healthy=None
    try:
        healthy=p2p.connect(server.address,timeout=1.0)
        status=p2p.request(healthy,{"type":"get_status"})
        ok("healthy outbound request preserved",status["tip_hash"]==chain.tip.hash())
        ok("healthy request restores socket timeout",healthy.gettimeout()==1.0)
    finally:
        if healthy is not None:
            try:healthy.close()
            except OSError:pass
        server.stop()

    print(f"SEC-089 outbound P2P receive deadline: {len(checks)}/{len(checks)} GREEN")

if __name__=="__main__":main()
