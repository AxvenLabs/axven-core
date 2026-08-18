#!/usr/bin/env python3
"""Axven P2P transport — checkpoint 4.

Length-prefixed JSON framing, identity-bound handshake, tx/block propagation,
orphan-safe block acceptance, and locator-based active-chain sync.
"""
from __future__ import annotations
import json, socket, struct, threading
from typing import Any, Dict, Optional
import axven

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 16 * 1024 * 1024
INBOUND_PEER_TIMEOUT = 5.0
MAX_SYNC_BLOCKS = 128
MAX_LOCATOR_HASHES = 64
MAX_P2P_TX_INPUTS = 1024
MAX_P2P_TX_OUTPUTS = 1024

class ProtocolError(ValueError): pass

def local_identity() -> Dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "chain_id": axven.CHAIN_ID,
        "config_fingerprint": axven.CONFIG_FINGERPRINT,
        "genesis_hash": axven._genesis().hash(),
    }

def validate_handshake(msg: Dict[str, Any]) -> None:
    expected=local_identity()
    if msg.get("type") != "hello": raise ProtocolError("expected hello")
    for key in ("protocol_version","chain_id","config_fingerprint","genesis_hash"):
        if msg.get(key) != expected[key]:
            raise ProtocolError(f"{key} mismatch")

def send_message(sock: socket.socket, msg: Dict[str, Any]) -> None:
    raw=json.dumps(msg,sort_keys=True,separators=(",",":")).encode()
    if len(raw)>MAX_MESSAGE_BYTES: raise ProtocolError("message too large")
    sock.sendall(struct.pack(">I",len(raw))+raw)

def _recv_exact(sock,n):
    out=bytearray()
    while len(out)<n:
        chunk=sock.recv(n-len(out))
        if not chunk: raise EOFError("peer closed")
        out.extend(chunk)
    return bytes(out)

def recv_message(sock: socket.socket) -> Dict[str, Any]:
    n=struct.unpack(">I",_recv_exact(sock,4))[0]
    if n<=0 or n>MAX_MESSAGE_BYTES: raise ProtocolError("invalid message length")
    try: msg=json.loads(_recv_exact(sock,n))
    except Exception as e: raise ProtocolError("invalid json") from e
    if not isinstance(msg,dict): raise ProtocolError("message must be object")
    return msg

def hello_message():
    return {"type":"hello",**local_identity()}

def handshake(sock: socket.socket) -> Dict[str, Any]:
    send_message(sock,hello_message())
    peer=recv_message(sock)
    validate_handshake(peer)
    return peer

class PeerSession:
    def __init__(self, chain: axven.Blockchain, mempool: Optional[axven.Mempool]=None):
        self.chain=chain
        self.mempool=mempool

    def status(self):
        with self.chain._state_lock:
            tip=self.chain.tip
            return {
                "type":"status",
                "height":tip.height,
                "tip_hash":tip.hash(),
                "chainwork":self.chain.chainwork,
            }

    def locator(self):
        with self.chain._state_lock:
            # Simple checkpoint locator; sufficient for rebuilt devnet.
            hs=[]; step=1; i=len(self.chain.blocks)-1
            while i>=0:
                hs.append(self.chain.blocks[i].hash())
                if len(hs)>10: step*=2
                i-=step
            if self.chain.blocks[0].hash() not in hs:
                hs.append(self.chain.blocks[0].hash())
            return hs

    def handle(self,msg):
        typ=msg.get("type")
        if typ=="status": return None
        if typ=="get_status": return self.status()
        if typ=="tx":
            if self.mempool is None: raise ProtocolError("mempool unavailable")
            raw_tx=msg.get("tx")
            if not isinstance(raw_tx,dict):
                raise ProtocolError("tx must be object")
            raw_inputs=raw_tx.get("inputs",[])
            raw_outputs=raw_tx.get("outputs",[])
            if not isinstance(raw_inputs,list):
                raise ProtocolError("tx inputs must be list")
            if not isinstance(raw_outputs,list):
                raise ProtocolError("tx outputs must be list")
            if len(raw_inputs)>MAX_P2P_TX_INPUTS:
                raise ProtocolError("too many tx inputs")
            if len(raw_outputs)>MAX_P2P_TX_OUTPUTS:
                raise ProtocolError("too many tx outputs")
            tx=axven.Transaction.from_dict(raw_tx)
            tid=self.mempool.add(tx)
            return {"type":"accepted","kind":"tx","id":tid}
        if typ=="block":
            block=axven.Block.from_dict(msg["block"])
            ok,status=self.chain.add_block(block)
            if not ok and status not in ("duplicate","orphan"):
                raise ProtocolError(f"block rejected: {status}")
            return {"type":"accepted","kind":"block","id":block.hash(),"status":status}
        if typ=="get_blocks":
            raw_locator=msg.get("locator") or []
            if not isinstance(raw_locator,list):
                raise ProtocolError("locator must be list")
            if len(raw_locator)>MAX_LOCATOR_HASHES:
                raise ProtocolError("locator too large")
            locator=list(raw_locator)

            try:
                limit=int(msg.get("limit",128))
            except (TypeError,ValueError):
                raise ProtocolError("invalid block limit")
            if limit<1 or limit>MAX_SYNC_BLOCKS:
                raise ProtocolError("invalid block limit")

            with self.chain._state_lock:
                active={b.hash():i for i,b in enumerate(self.chain.blocks)}
                start=0
                for h in locator:
                    if h in active:
                        start=active[h]+1
                        break
                blocks=list(
                    self.chain.blocks[
                        start:start+limit
                    ]
                )
            return {
                "type":"blocks",
                "blocks":[b.to_dict() for b in blocks],
            }
        if typ=="blocks":
            raw_blocks=msg.get("blocks",[])
            if not isinstance(raw_blocks,list):
                raise ProtocolError("blocks must be list")
            if len(raw_blocks)>MAX_SYNC_BLOCKS:
                raise ProtocolError("too many blocks")
            accepted=0
            for raw in raw_blocks:
                b=axven.Block.from_dict(raw)
                ok,status=self.chain.add_block(b)
                if ok or status=="duplicate": accepted+=1
                elif status=="orphan": continue
                else: raise ProtocolError(f"sync block rejected: {status}")
            return {"type":"accepted","kind":"blocks","count":accepted}
        raise ProtocolError("unknown message type")

def serve_connection(sock,session:PeerSession):
    try:
        handshake(sock)
        while True:
            msg=recv_message(sock)
            reply=session.handle(msg)
            if reply is not None: send_message(sock,reply)
    except (EOFError,OSError,ProtocolError,KeyError,TypeError,ValueError):
        return
    finally:
        try:sock.close()
        except OSError:pass

def sync_once(sock,session:PeerSession,limit=128):
    send_message(sock,{"type":"get_blocks","locator":session.locator(),"limit":limit})
    msg=recv_message(sock)
    if msg.get("type")!="blocks": raise ProtocolError("expected blocks")
    return session.handle(msg)


class NodeServer:
    """Small threaded TCP node wrapper for integration/devnet operation."""
    def __init__(self, chain=None, mempool=None, host="127.0.0.1", port=0):
        self.chain=chain or axven.Blockchain()
        self.mempool=mempool or axven.Mempool(self.chain)
        self.session=PeerSession(self.chain,self.mempool)
        self.host=host; self.port=port
        self._sock=None; self._thread=None; self._stop=threading.Event()
        self._clients=set(); self._lock=threading.Lock()

    @property
    def address(self):
        if self._sock is None:return (self.host,self.port)
        return self._sock.getsockname()

    def start(self):
        if self._sock is not None:return self
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        sock.bind((self.host,self.port)); sock.listen(16); sock.settimeout(.2)
        self._sock=sock
        def loop():
            while not self._stop.is_set():
                try: c,_=sock.accept()
                except socket.timeout: continue
                except OSError: break
                c.settimeout(INBOUND_PEER_TIMEOUT)
                with self._lock:self._clients.add(c)
                def worker(client=c):
                    try: serve_connection(client,self.session)
                    finally:
                        with self._lock:self._clients.discard(client)
                threading.Thread(target=worker,daemon=True).start()
        self._thread=threading.Thread(target=loop,daemon=True); self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        if self._sock:
            try:self._sock.close()
            except OSError:pass
        with self._lock:
            for c in list(self._clients):
                try:c.close()
                except OSError:pass
        if self._thread:self._thread.join(1)
        self._sock=None

def connect(address,timeout=3.0):
    s=socket.create_connection(address,timeout=timeout)
    s.settimeout(timeout)
    handshake(s)
    return s

def request(sock,msg):
    send_message(sock,msg)
    return recv_message(sock)

def sync_to_peer(address,session,limit=128,max_rounds=100):
    """Reconnect-friendly catch-up until the peer returns no more blocks."""
    total=0
    sock=connect(address)
    try:
        for _ in range(max_rounds):
            reply=request(sock,{"type":"get_blocks","locator":session.locator(),"limit":limit})
            if reply.get("type")!="blocks":raise ProtocolError("expected blocks")
            blocks=reply.get("blocks",[])
            if not blocks:break
            result=session.handle(reply); total+=result["count"]
            if len(blocks)<limit:break
        return total
    finally:
        try:sock.close()
        except OSError:pass

def propagate_tx(address,tx):
    sock=connect(address)
    try:return request(sock,{"type":"tx","tx":tx.to_dict()})
    finally:sock.close()

def propagate_block(address,block):
    sock=connect(address)
    try:return request(sock,{"type":"block","block":block.to_dict()})
    finally:sock.close()
