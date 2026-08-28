#!/usr/bin/env python3
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
