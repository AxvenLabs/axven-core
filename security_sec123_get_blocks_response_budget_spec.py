#!/usr/bin/env python3
"""SEC-123 bound public get_blocks response serialization/egress work."""

import inspect
import socket
import axven
import p2p


class FakeClock:
    def __init__(self):
        self.now=1000.0
    def __call__(self):
        return self.now
    def advance(self,seconds):
        self.now+=seconds


class RecordingLease:
    def __init__(self):
        self.actual=None
        self.cancelled=False
    def settle(self,actual):
        self.actual=actual
    def cancel(self):
        self.cancelled=True


def main():
    checks=[]
    def green(name,cond):
        assert cond,name
        checks.append(name)
        print("[GREEN]",name)

    green(
        "response byte budgets admit multiple maximum frames but bound sustained egress",
        p2p.INBOUND_SYNC_RESPONSE_BYTE_PER_HOST_BURST >= 4*p2p.MAX_MESSAGE_BYTES
        and p2p.INBOUND_SYNC_RESPONSE_BYTE_GLOBAL_BURST
            >= 2*p2p.INBOUND_SYNC_RESPONSE_BYTE_PER_HOST_BURST
        and 0 < p2p.INBOUND_SYNC_RESPONSE_BYTE_PER_HOST_RATE
            < p2p.INBOUND_SYNC_RESPONSE_BYTE_PER_HOST_BURST,
    )

    clock=FakeClock()
    limiter=p2p._InboundSyncResponseByteLimiter(
        clock=clock, global_rate=8, global_burst=64,
        per_host_rate=4, per_host_burst=32, max_hosts=4,
    )
    lease=limiter.reserve("192.0.2.1",16)
    green("maximum response reservation succeeds within fresh host burst",lease is not None)
    lease.settle(4)
    green(
        "unused reservation bytes are refunded and only actual bytes remain charged",
        limiter.snapshot()["global_tokens"] == 60,
    )
    second=limiter.reserve("192.0.2.1",16)
    green("refunded capacity is immediately reusable on the same source",second is not None)
    second.cancel()
    green(
        "cancelled response build restores its entire reservation",
        limiter.snapshot()["global_tokens"] == 60,
    )

    host=p2p._InboundSyncResponseByteLimiter(
        clock=FakeClock(), global_rate=1, global_burst=64,
        per_host_rate=1, per_host_burst=16, max_hosts=4,
    )
    held=host.reserve("198.51.100.1",16)
    green(
        "same source cannot reserve beyond its response-byte burst",
        held is not None and host.reserve("198.51.100.1",16) is None,
    )
    green(
        "independent source still has its own bounded response capacity",
        host.reserve("198.51.100.2",16) is not None,
    )

    global_limit=p2p._InboundSyncResponseByteLimiter(
        clock=FakeClock(), global_rate=1, global_burst=32,
        per_host_rate=1, per_host_burst=32, max_hosts=4,
    )
    g1=global_limit.reserve("203.0.113.1",16)
    g2=global_limit.reserve("203.0.113.2",16)
    green(
        "distributed sources remain globally bounded",
        g1 is not None and g2 is not None
        and global_limit.reserve("203.0.113.3",16) is None,
    )

    bounded_hosts=p2p._InboundSyncResponseByteLimiter(
        clock=FakeClock(), global_rate=100, global_burst=100,
        per_host_rate=100, per_host_burst=100, max_hosts=2,
    )
    for i in range(6):
        lease_i=bounded_hosts.reserve(f"192.0.2.{i+1}",1)
        assert lease_i is not None
        lease_i.settle(1)
    green("response limiter source memory is independently bounded",bounded_hosts.snapshot()["hosts"] <= 2)

    refill_clock=FakeClock()
    refill=p2p._InboundSyncResponseByteLimiter(
        clock=refill_clock, global_rate=8, global_burst=16,
        per_host_rate=8, per_host_burst=16, max_hosts=2,
    )
    refill_lease=refill.reserve("192.0.2.10",16)
    assert refill_lease is not None
    refill_lease.settle(16)
    green("exhausted fresh byte burst rejects another maximum response",refill.reserve("192.0.2.10",16) is None)
    refill_clock.advance(2.0)
    resumed=refill.reserve("192.0.2.10",16)
    green("response byte budget refills without reconnect reset",resumed is not None)
    if resumed is not None:
        resumed.cancel()

    wallet=axven.Wallet()
    chain=axven.Blockchain()
    for _ in range(5):
        chain.mine(wallet.address)
    session=p2p.PeerSession(chain,None)
    msg={"type":"get_blocks","locator":[chain.blocks[0].hash()],"limit":3}

    original_json=p2p._json_bytes
    json_calls=[]
    def trap_json(value):
        json_calls.append(value)
        raise AssertionError("response serialization reached without byte reservation")
    p2p._json_bytes=trap_json
    try:
        try:
            session.handle(msg,sync_response_byte_reserve=lambda cost: None)
            blocked=False
        except p2p.ProtocolError as exc:
            blocked=("sync response byte budget exceeded" in str(exc))
    finally:
        p2p._json_bytes=original_json
    green(
        "exhausted response budget stops before any response JSON serialization",
        blocked and not json_calls,
    )

    record=RecordingLease()
    reply=session.handle(msg,sync_response_byte_reserve=lambda cost: record)
    exact_size=len(p2p._json_bytes(reply))
    green(
        "healthy response settles reservation to exact serialized reply size",
        record.actual == exact_size and not record.cancelled
        and reply["type"] == "blocks" and len(reply["blocks"]) == 3,
    )

    failing=RecordingLease()
    original_json=p2p._json_bytes
    def fail_json(value):
        raise RuntimeError("synthetic response build failure")
    p2p._json_bytes=fail_json
    try:
        try:
            session.handle(msg,sync_response_byte_reserve=lambda cost: failing)
        except RuntimeError:
            failed=True
        else:
            failed=False
    finally:
        p2p._json_bytes=original_json
    green("failed response construction refunds the full reservation",failed and failing.cancelled)

    plain=session.handle(msg)
    green(
        "unmetered direct session behavior remains compatible",
        plain["type"] == "blocks" and len(plain["blocks"]) == 3,
    )

    class RejectLimiter:
        def __init__(self): self.calls=[]
        def reserve(self,host,cost):
            self.calls.append((host,cost)); return None

    server=p2p.NodeServer(chain,None,host="127.0.0.1",port=0)
    reject=RejectLimiter()
    server._sync_response_byte_limiter=reject
    server.start()
    try:
        sock=p2p.connect(server.address)
        try:
            try:
                p2p.request(sock,{"type":"get_blocks","locator":[],"limit":1})
                wire_blocked=False
            except (EOFError,OSError,p2p.ProtocolError):
                wire_blocked=True
        finally:
            try:sock.close()
            except OSError:pass
        green(
            "public listener enforces response reservation before serving get_blocks",
            wire_blocked and reject.calls
            and reject.calls[0][1] == p2p.MAX_MESSAGE_BYTES,
        )

        server._sync_response_byte_limiter=p2p._InboundSyncResponseByteLimiter()
        sock2=p2p.connect(server.address)
        try:
            healthy=p2p.request(sock2,{"type":"get_blocks","locator":[],"limit":1})
        finally:
            sock2.close()
        green(
            "healthy public sync response remains available after limiter recovery",
            healthy.get("type") == "blocks" and len(healthy.get("blocks",[])) == 1,
        )
    finally:
        server.stop()

    handle_src=inspect.getsource(p2p.PeerSession.handle)
    serve_src=inspect.getsource(p2p.serve_connection)
    server_src=inspect.getsource(p2p.NodeServer)
    green(
        "production wiring reserves maximum response before build and settles actual bytes",
        "sync_response_byte_reserve(MAX_MESSAGE_BYTES)" in handle_src
        and "response_lease.settle(reply_size)" in handle_src
        and "response_lease.cancel()" in handle_src
        and "sync_response_byte_reserve=sync_response_byte_reserve" in serve_src
        and "_sync_response_byte_limiter" in server_src,
    )

    green(
        "SEC-122 inbound frame lifetime budget remains wired independently",
        "frame_byte_budget=self._frame_byte_budget" in server_src
        and hasattr(p2p,"MAX_INBOUND_INFLIGHT_FRAME_BYTES"),
    )

    print(f"SEC-123 get_blocks response budget: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
