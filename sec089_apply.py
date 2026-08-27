#!/usr/bin/env python3
"""Temporary SEC-089 patch generator; removed from final tree."""
from __future__ import annotations
import hashlib, json
from pathlib import Path

ROOT=Path(__file__).resolve().parent
P2P=ROOT/"p2p.py"
SPEC=ROOT/"security_sec089_p2p_outbound_recv_deadline_spec.py"
MANIFEST=ROOT/"release_manifest.json"
WORKFLOW=ROOT/".github"/"workflows"/"sec089_apply.yml"

def write_lf(path,text):
    with path.open("w",encoding="utf-8",newline="\n") as f:f.write(text)

def replace_once(text,old,new,label):
    n=text.count(old)
    if n!=1: raise RuntimeError(f"{label}: expected 1 match, found {n}")
    return text.replace(old,new,1)

p=P2P.read_text(encoding="utf-8")
p=replace_once(p,
'''INBOUND_PEER_TIMEOUT = 5.0
INBOUND_MESSAGE_DEADLINE = 30.0
MAX_INBOUND_PEERS = 32
''',
'''INBOUND_PEER_TIMEOUT = 5.0
INBOUND_MESSAGE_DEADLINE = 30.0
OUTBOUND_MESSAGE_DEADLINE = 30.0
MAX_INBOUND_PEERS = 32
''',"outbound deadline constant")
p=replace_once(p,
'''def sync_once(sock,session:PeerSession,limit=128):
    send_message(sock,{"type":"get_blocks","locator":session.locator(),"limit":limit})
    msg=recv_message(sock)
    if msg.get("type")!="blocks": raise ProtocolError("expected blocks")
    return session.handle(msg)
''',
'''def sync_once(sock,session:PeerSession,limit=128):
    msg=request(
        sock,
        {"type":"get_blocks","locator":session.locator(),"limit":limit},
    )
    if msg.get("type")!="blocks": raise ProtocolError("expected blocks")
    return session.handle(msg)
''',"sync_once request path")
p=replace_once(p,
'''def connect(address,timeout=3.0):
    s=socket.create_connection(address,timeout=timeout)
    s.settimeout(timeout)
    handshake(s)
    return s

def request(sock,msg):
    send_message(sock,msg)
    return recv_message(sock)
''',
'''def connect(address,timeout=3.0):
    s=socket.create_connection(address,timeout=timeout)
    s.settimeout(timeout)
    deadline=(None if timeout is None else time.monotonic()+timeout)
    try:
        handshake(s,deadline=deadline)
    except Exception:
        try:s.close()
        except OSError:pass
        raise
    s.settimeout(timeout)
    return s

def request(sock,msg,deadline=None):
    send_message(sock,msg)
    if deadline is None:
        deadline=time.monotonic()+OUTBOUND_MESSAGE_DEADLINE
    original_timeout=sock.gettimeout()
    try:
        return recv_message(sock,deadline=deadline)
    finally:
        try:sock.settimeout(original_timeout)
        except OSError:pass
''',"bounded outbound connect/request")
if not p.endswith("\n"):p+="\n"
write_lf(P2P,p)

spec='''#!/usr/bin/env python3
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
'''
write_lf(SPEC,spec)

manifest=json.loads(MANIFEST.read_text(encoding="utf-8"))
for path in (P2P,SPEC):
    data=path.read_bytes()
    manifest["files"][path.name]={"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
with MANIFEST.open("w",encoding="utf-8",newline="\n") as f:
    json.dump(manifest,f,indent=2); f.write("\n")
Path(__file__).unlink()
if WORKFLOW.exists():WORKFLOW.unlink()
