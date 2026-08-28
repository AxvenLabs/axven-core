#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_lf(path: Path) -> str:
    return path.read_bytes().replace(b"\r\n", b"\n").decode("utf-8")


def write_lf(path: Path, text: str) -> None:
    path.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"SEC-122 patch anchor {label!r}: expected 1 match, got {count}")
    return text.replace(old, new, 1)


p2p_path = ROOT / "p2p.py"
p2p = read_lf(p2p_path)

p2p = replace_once(
    p2p,
    "MAX_INBOUND_PEERS = 32\nMAX_INBOUND_PEERS_PER_HOST = 4\n",
    "MAX_INBOUND_PEERS = 32\n"
    "MAX_INBOUND_PEERS_PER_HOST = 4\n"
    "# A per-frame 16 MiB cap still permits 32 workers to retain roughly\n"
    "# 512 MiB of attacker-selected wire payload concurrently, before decoded\n"
    "# JSON object overhead.  Bound post-handshake in-flight frame bytes across\n"
    "# the whole listener.  This is transport resource policy only.\n"
    "MAX_INBOUND_INFLIGHT_FRAME_BYTES = 64 * 1024 * 1024\n",
    "aggregate frame constant",
)

p2p = replace_once(
    p2p,
    "class ProtocolError(ValueError): pass\n\n"
    "def _work_budget_status(status):\n",
    "class ProtocolError(ValueError): pass\n\n"
    "class _InboundFrameLease:\n"
    "    def __init__(self,budget,size):\n"
    "        self._budget=budget\n"
    "        self._size=size\n"
    "        self._released=False\n\n"
    "    def release(self):\n"
    "        if self._released:\n"
    "            return\n"
    "        self._released=True\n"
    "        self._budget._release(self._size)\n\n\n"
    "class _InboundFrameByteBudget:\n"
    "    \"\"\"Non-blocking listener-wide reservation for decoded frame lifetime.\"\"\"\n"
    "    def __init__(self,max_bytes=MAX_INBOUND_INFLIGHT_FRAME_BYTES):\n"
    "        if type(max_bytes) is not int or max_bytes < MAX_MESSAGE_BYTES:\n"
    "            raise ValueError(\"invalid inbound frame byte budget\")\n"
    "        self._max_bytes=max_bytes\n"
    "        self._inflight_bytes=0\n"
    "        self._peak_bytes=0\n"
    "        self._lock=threading.Lock()\n\n"
    "    def reserve(self,size):\n"
    "        if type(size) is not int or size <= 0 or size > MAX_MESSAGE_BYTES:\n"
    "            return None\n"
    "        with self._lock:\n"
    "            if self._inflight_bytes + size > self._max_bytes:\n"
    "                return None\n"
    "            self._inflight_bytes += size\n"
    "            self._peak_bytes=max(self._peak_bytes,self._inflight_bytes)\n"
    "        return _InboundFrameLease(self,size)\n\n"
    "    def _release(self,size):\n"
    "        with self._lock:\n"
    "            self._inflight_bytes -= size\n"
    "            if self._inflight_bytes < 0:\n"
    "                raise RuntimeError(\"inbound frame byte accounting underflow\")\n\n"
    "    def snapshot(self):\n"
    "        with self._lock:\n"
    "            return {\n"
    "                \"max_bytes\":self._max_bytes,\n"
    "                \"inflight_bytes\":self._inflight_bytes,\n"
    "                \"peak_bytes\":self._peak_bytes,\n"
    "            }\n\n\n"
    "def _work_budget_status(status):\n",
    "frame budget classes",
)

old_recv = '''def recv_message(sock: socket.socket,deadline=None,max_bytes=None) -> Dict[str, Any]:
    frame_limit=MAX_MESSAGE_BYTES if max_bytes is None else max_bytes
    if type(frame_limit) is not int or frame_limit <= 0:
        raise ProtocolError("invalid message byte limit")
    n=struct.unpack(">I",_recv_exact(sock,4,deadline))[0]
    if n<=0 or n>frame_limit: raise ProtocolError("invalid message length")
    try:
        msg=json.loads(_recv_exact(sock,n,deadline),object_pairs_hook=_reject_duplicate_json_keys)
    except ProtocolError:
        raise
    except Exception as e:
        raise ProtocolError("invalid json") from e
    if not isinstance(msg,dict): raise ProtocolError("message must be object")
    return msg
'''
new_recv = '''def _recv_message_with_lease(
    sock: socket.socket, deadline=None, max_bytes=None, frame_byte_budget=None,
):
    frame_limit=MAX_MESSAGE_BYTES if max_bytes is None else max_bytes
    if type(frame_limit) is not int or frame_limit <= 0:
        raise ProtocolError("invalid message byte limit")
    n=struct.unpack(">I",_recv_exact(sock,4,deadline))[0]
    if n<=0 or n>frame_limit:
        raise ProtocolError("invalid message length")

    lease=None
    if frame_byte_budget is not None:
        lease=frame_byte_budget.reserve(n)
        if lease is None:
            raise ProtocolError("inbound frame byte budget exceeded")

    try:
        raw=_recv_exact(sock,n,deadline)
        try:
            msg=json.loads(raw,object_pairs_hook=_reject_duplicate_json_keys)
        except ProtocolError:
            raise
        except Exception as e:
            raise ProtocolError("invalid json") from e
        if not isinstance(msg,dict):
            raise ProtocolError("message must be object")
        return msg,lease
    except Exception:
        if lease is not None:
            lease.release()
        raise


def recv_message(sock: socket.socket,deadline=None,max_bytes=None) -> Dict[str, Any]:
    msg,lease=_recv_message_with_lease(
        sock,deadline=deadline,max_bytes=max_bytes,frame_byte_budget=None,
    )
    if lease is not None:
        lease.release()
    return msg
'''
p2p = replace_once(p2p, old_recv, new_recv, "leased receive helper")

old_serve = '''def serve_connection(
    sock, session:PeerSession, block_work_gate=None, tx_work_gate=None,
    block_signature_work_gate=None,
):
    try:
        handshake(sock,deadline=time.monotonic()+INBOUND_PEER_TIMEOUT)
        sock.settimeout(INBOUND_PEER_TIMEOUT)
        while True:
            msg=recv_message(
                sock,
                deadline=time.monotonic()+INBOUND_MESSAGE_DEADLINE,
            )
            sock.settimeout(INBOUND_PEER_TIMEOUT)
            if tx_work_gate is not None or block_signature_work_gate is not None:
                reply=session.handle(
                    msg,
                    block_work_gate=block_work_gate,
                    tx_work_gate=tx_work_gate,
                    block_signature_work_gate=block_signature_work_gate,
                )
            elif block_work_gate is not None:
                reply=session.handle(msg,block_work_gate=block_work_gate)
            else:
                reply=session.handle(msg)
            if reply is not None: send_message(sock,reply)
    except (EOFError,OSError,ProtocolError,KeyError,TypeError,ValueError):
        return
    finally:
        try:sock.close()
        except OSError:pass
'''
new_serve = '''def serve_connection(
    sock, session:PeerSession, block_work_gate=None, tx_work_gate=None,
    block_signature_work_gate=None, frame_byte_budget=None,
):
    try:
        handshake(sock,deadline=time.monotonic()+INBOUND_PEER_TIMEOUT)
        sock.settimeout(INBOUND_PEER_TIMEOUT)
        while True:
            lease=None
            try:
                if frame_byte_budget is None:
                    msg=recv_message(
                        sock,
                        deadline=time.monotonic()+INBOUND_MESSAGE_DEADLINE,
                    )
                else:
                    msg,lease=_recv_message_with_lease(
                        sock,
                        deadline=time.monotonic()+INBOUND_MESSAGE_DEADLINE,
                        frame_byte_budget=frame_byte_budget,
                    )
                sock.settimeout(INBOUND_PEER_TIMEOUT)
                if tx_work_gate is not None or block_signature_work_gate is not None:
                    reply=session.handle(
                        msg,
                        block_work_gate=block_work_gate,
                        tx_work_gate=tx_work_gate,
                        block_signature_work_gate=block_signature_work_gate,
                    )
                elif block_work_gate is not None:
                    reply=session.handle(msg,block_work_gate=block_work_gate)
                else:
                    reply=session.handle(msg)
                if reply is not None:
                    send_message(sock,reply)
            finally:
                if lease is not None:
                    lease.release()
    except (EOFError,OSError,ProtocolError,KeyError,TypeError,ValueError):
        return
    finally:
        try:sock.close()
        except OSError:pass
'''
p2p = replace_once(p2p, old_serve, new_serve, "serve lease lifetime")

p2p = replace_once(
    p2p,
    "        self._block_signature_work_limiter=_InboundBlockSignatureWorkLimiter()\n",
    "        self._block_signature_work_limiter=_InboundBlockSignatureWorkLimiter()\n"
    "        self._frame_byte_budget=_InboundFrameByteBudget()\n",
    "NodeServer frame budget",
)

p2p = replace_once(
    p2p,
    "                            block_signature_work_gate=block_signature_gate,\n"
    "                        )\n",
    "                            block_signature_work_gate=block_signature_gate,\n"
    "                            frame_byte_budget=self._frame_byte_budget,\n"
    "                        )\n",
    "NodeServer worker wiring",
)

write_lf(p2p_path, p2p)

spec = r'''#!/usr/bin/env python3
"""SEC-122 bound aggregate post-handshake inbound P2P frame memory."""

import inspect
import json
import socket
import struct
import threading
import time

import axven
import p2p


class MemorySocket:
    def __init__(self, raw):
        self.raw=bytearray(raw)
        self.timeout=None
        self.recv_bytes=0
        self.recv_calls=0
    def recv(self,n):
        self.recv_calls+=1
        if not self.raw:
            return b""
        out=bytes(self.raw[:n])
        del self.raw[:n]
        self.recv_bytes+=len(out)
        return out
    def gettimeout(self):
        return self.timeout
    def settimeout(self,value):
        self.timeout=value


def frame(msg):
    raw=json.dumps(msg,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    return struct.pack(">I",len(raw))+raw, len(raw)


class BlockingSession:
    def __init__(self,inner,entered,release):
        self.inner=inner
        self.entered=entered
        self.release=release
    def handle(self,msg,*args,**kwargs):
        self.entered.set()
        if not self.release.wait(3):
            raise RuntimeError("SEC-122 dispatch release timeout")
        return self.inner.handle(msg,*args,**kwargs)


def main():
    checks=[]
    def green(name,cond):
        assert cond,name
        checks.append(name)
        print("[GREEN]",name)

    green(
        "listener-wide in-flight frame budget pinned at 64 MiB",
        p2p.MAX_INBOUND_INFLIGHT_FRAME_BYTES == 64 * 1024 * 1024
        and p2p.MAX_INBOUND_INFLIGHT_FRAME_BYTES >= p2p.MAX_MESSAGE_BYTES
        and p2p.MAX_INBOUND_INFLIGHT_FRAME_BYTES
            < p2p.MAX_INBOUND_PEERS * p2p.MAX_MESSAGE_BYTES,
    )

    budget=p2p._InboundFrameByteBudget()
    leases=[budget.reserve(p2p.MAX_MESSAGE_BYTES) for _ in range(4)]
    green(
        "four maximum frames fit aggregate budget exactly",
        all(lease is not None for lease in leases)
        and budget.snapshot()["inflight_bytes"] == p2p.MAX_INBOUND_INFLIGHT_FRAME_BYTES,
    )
    green(
        "fifth concurrent maximum frame is rejected without overcommit",
        budget.reserve(p2p.MAX_MESSAGE_BYTES) is None
        and budget.snapshot()["inflight_bytes"] == p2p.MAX_INBOUND_INFLIGHT_FRAME_BYTES,
    )
    leases[0].release()
    replacement=budget.reserve(p2p.MAX_MESSAGE_BYTES)
    green(
        "released aggregate frame capacity is immediately reusable",
        replacement is not None
        and budget.snapshot()["inflight_bytes"] == p2p.MAX_INBOUND_INFLIGHT_FRAME_BYTES,
    )
    replacement.release()
    for lease in leases[1:]:
        lease.release()
    green(
        "frame lease release returns aggregate accounting to zero",
        budget.snapshot()["inflight_bytes"] == 0,
    )

    raw,n=frame({"type":"get_status"})
    held_budget=p2p._InboundFrameByteBudget()
    sock=MemorySocket(raw)
    msg,lease=p2p._recv_message_with_lease(sock,frame_byte_budget=held_budget)
    green(
        "successful receive keeps declared frame bytes reserved after parse",
        msg == {"type":"get_status"}
        and lease is not None
        and held_budget.snapshot()["inflight_bytes"] == n,
    )
    lease.release()
    green(
        "successful receive lease explicitly releases after dispatch lifetime",
        held_budget.snapshot()["inflight_bytes"] == 0,
    )

    malformed=b"{not-json"
    malformed_sock=MemorySocket(struct.pack(">I",len(malformed))+malformed)
    malformed_budget=p2p._InboundFrameByteBudget()
    try:
        p2p._recv_message_with_lease(
            malformed_sock,frame_byte_budget=malformed_budget
        )
        malformed_failed=False
    except p2p.ProtocolError:
        malformed_failed=True
    green(
        "parse failure releases aggregate frame reservation",
        malformed_failed and malformed_budget.snapshot()["inflight_bytes"] == 0,
    )

    small_budget=p2p._InboundFrameByteBudget(max_bytes=p2p.MAX_MESSAGE_BYTES)
    occupied=small_budget.reserve(p2p.MAX_MESSAGE_BYTES)
    prefix_only=MemorySocket(struct.pack(">I",p2p.MAX_MESSAGE_BYTES))
    try:
        p2p._recv_message_with_lease(
            prefix_only,frame_byte_budget=small_budget
        )
        blocked=False
    except p2p.ProtocolError as exc:
        blocked="frame byte budget exceeded" in str(exc)
    green(
        "aggregate saturation rejects after prefix before frame body read",
        blocked and prefix_only.recv_bytes == 4 and prefix_only.recv_calls == 1,
    )
    occupied.release()

    legacy_raw,_=frame({"type":"get_status"})
    legacy=p2p.recv_message(MemorySocket(legacy_raw))
    green(
        "legacy standalone recv_message API remains compatible",
        legacy == {"type":"get_status"},
    )

    chain=axven.Blockchain()
    server=p2p.NodeServer(chain,None,host="127.0.0.1",port=0)
    entered=threading.Event()
    release_dispatch=threading.Event()
    server.session=BlockingSession(server.session,entered,release_dispatch)
    server.start()
    client=None
    try:
        client=p2p.connect(server.address)
        p2p.send_message(client,{"type":"get_status"})
        green(
            "server dispatch reached while post-handshake frame lease is live",
            entered.wait(2),
        )
        snapshot=server._frame_byte_budget.snapshot()
        green(
            "NodeServer holds frame reservation through session dispatch",
            snapshot["inflight_bytes"] > 0,
        )
        release_dispatch.set()
        reply=p2p.recv_message(client,deadline=time.monotonic()+2)
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            if server._frame_byte_budget.snapshot()["inflight_bytes"] == 0:
                break
            time.sleep(0.01)
        green(
            "NodeServer releases frame reservation after dispatch and reply",
            reply.get("type") == "status"
            and server._frame_byte_budget.snapshot()["inflight_bytes"] == 0,
        )
        p2p.send_message(client,{"type":"get_status"})
        entered.clear()
    finally:
        release_dispatch.set()
        if client is not None:
            try: client.close()
            except OSError: pass
        server.stop()

    recv_src=inspect.getsource(p2p._recv_message_with_lease)
    serve_src=inspect.getsource(p2p.serve_connection)
    server_src=inspect.getsource(p2p.NodeServer)
    handshake_src=inspect.getsource(p2p.handshake)
    request_src=inspect.getsource(p2p.request)
    green(
        "production wiring reserves before body and releases only after handling",
        "frame_byte_budget.reserve(n)" in recv_src
        and "_recv_exact(sock,n,deadline)" in recv_src
        and recv_src.index("frame_byte_budget.reserve(n)") < recv_src.index("_recv_exact(sock,n,deadline)")
        and "finally:" in serve_src
        and "lease.release()" in serve_src
        and "frame_byte_budget=self._frame_byte_budget" in server_src,
    )
    green(
        "handshake and outbound receive paths remain outside inbound aggregate budget",
        "frame_byte_budget" not in handshake_src
        and "frame_byte_budget" not in request_src,
    )

    print(f"SEC-122 inbound in-flight frame budget: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
'''
spec_path=ROOT / "security_sec122_p2p_inflight_frame_budget_spec.py"
write_lf(spec_path,spec)

manifest_path=ROOT / "release_manifest.json"
manifest=json.loads(read_lf(manifest_path))
for rel in ("p2p.py","security_sec122_p2p_inflight_frame_budget_spec.py"):
    raw=(ROOT / rel).read_bytes().replace(b"\r\n",b"\n")
    manifest["files"][rel]={
        "bytes":len(raw),
        "sha256":hashlib.sha256(raw).hexdigest(),
    }
write_lf(manifest_path,json.dumps(manifest,indent=2,sort_keys=True)+"\n")

print("SEC-122 patch helper applied")