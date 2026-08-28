#!/usr/bin/env python3
"""SEC-124 bound public post-handshake P2P message dispatch rate."""

import inspect
import socket
import time

import axven
import p2p


class FakeClock:
    def __init__(self):
        self.now = 1000.0
    def __call__(self):
        return self.now
    def advance(self, seconds):
        self.now += seconds


class RejectLimiter:
    def __init__(self):
        self.calls = []
    def consume(self, host):
        self.calls.append(host)
        return False


def wait_for(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def request_fails(sock, msg):
    try:
        p2p.request(sock, msg)
    except (EOFError, OSError, p2p.ProtocolError):
        return True
    return False


def main():
    checks = []
    def green(name, cond):
        assert cond, name
        checks.append(name)
        print("[GREEN]", name)

    green(
        "message budgets preserve fast healthy sync while bounding sustained dispatch",
        p2p.INBOUND_MESSAGE_PER_HOST_BURST >= 2 * p2p.MAX_SYNC_BLOCKS
        and p2p.INBOUND_MESSAGE_GLOBAL_BURST >= 4 * p2p.INBOUND_MESSAGE_PER_HOST_BURST
        and 0 < p2p.INBOUND_MESSAGE_PER_HOST_RATE < p2p.INBOUND_MESSAGE_PER_HOST_BURST
        and 0 < p2p.INBOUND_MESSAGE_GLOBAL_RATE < p2p.INBOUND_MESSAGE_GLOBAL_BURST,
    )

    clock = FakeClock()
    limiter = p2p._InboundMessageRateLimiter(
        clock=clock, global_rate=8, global_burst=8,
        per_host_rate=2, per_host_burst=3, max_hosts=4,
    )
    green(
        "single source post-handshake burst is bounded",
        all(limiter.consume("192.0.2.1") for _ in range(3))
        and not limiter.consume("192.0.2.1"),
    )
    clock.advance(0.5)
    green(
        "single source message budget refills at pinned rate",
        limiter.consume("192.0.2.1"),
    )

    global_clock = FakeClock()
    global_limit = p2p._InboundMessageRateLimiter(
        clock=global_clock, global_rate=1, global_burst=2,
        per_host_rate=10, per_host_burst=10, max_hosts=4,
    )
    green(
        "distributed sources remain globally message-rate bounded",
        global_limit.consume("198.51.100.1")
        and global_limit.consume("198.51.100.2")
        and not global_limit.consume("198.51.100.3"),
    )

    bounded_hosts = p2p._InboundMessageRateLimiter(
        clock=FakeClock(), global_rate=100, global_burst=100,
        per_host_rate=100, per_host_burst=100, max_hosts=2,
    )
    for i in range(8):
        assert bounded_hosts.consume(f"203.0.113.{i+1}")
    green(
        "message limiter source memory is independently bounded",
        bounded_hosts.snapshot()["hosts"] <= 2,
    )

    wallet = axven.Wallet()
    chain = axven.Blockchain()
    chain.mine(wallet.address)

    # Reconnects must not create a fresh per-host burst. NodeServer owns the
    # limiter, while each worker only closes over the source host.
    reconnect_clock = FakeClock()
    reconnect_limiter = p2p._InboundMessageRateLimiter(
        clock=reconnect_clock, global_rate=0.001, global_burst=8,
        per_host_rate=0.001, per_host_burst=1, max_hosts=8,
    )
    server = p2p.NodeServer(chain, None, host="127.0.0.1", port=0)
    server._message_rate_limiter = reconnect_limiter
    server.start()
    try:
        first = p2p.connect(server.address)
        try:
            first_reply = p2p.request(first, {"type":"get_status"})
        finally:
            first.close()
        second = p2p.connect(server.address)
        try:
            second_blocked = request_fails(second, {"type":"get_status"})
        finally:
            try: second.close()
            except OSError: pass
        green(
            "socket reconnect does not reset same-host message budget",
            first_reply.get("type") == "status" and second_blocked,
        )
    finally:
        server.stop()

    # Exhausted budget must stop before any PeerSession dispatch. Handshake is
    # intentionally outside this gate so identity negotiation still completes.
    server = p2p.NodeServer(chain, None, host="127.0.0.1", port=0)
    reject = RejectLimiter()
    server._message_rate_limiter = reject
    handle_calls = []
    original_handle = server.session.handle
    def trap_handle(*args, **kwargs):
        handle_calls.append(args[0] if args else None)
        return original_handle(*args, **kwargs)
    server.session.handle = trap_handle
    server.start()
    try:
        sock = p2p.connect(server.address)
        handshake_ok = sock is not None
        try:
            blocked = request_fails(sock, {"type":"get_status"})
        finally:
            try: sock.close()
            except OSError: pass
        green(
            "handshake remains exempt while exhausted budget stops before dispatch",
            handshake_ok and blocked and reject.calls and not handle_calls,
        )
        green(
            "message-rate rejection releases SEC-122 frame lifetime reservation",
            wait_for(lambda: server._frame_byte_budget.snapshot()["inflight_bytes"] == 0),
        )
    finally:
        server.stop()

    # Unknown/cheap-invalid messages are also accounted before their semantic
    # validation can churn the session dispatcher.
    server = p2p.NodeServer(chain, None, host="127.0.0.1", port=0)
    reject = RejectLimiter()
    server._message_rate_limiter = reject
    invalid_handle_calls = []
    original_handle = server.session.handle
    def trap_invalid(*args, **kwargs):
        invalid_handle_calls.append(args[0] if args else None)
        return original_handle(*args, **kwargs)
    server.session.handle = trap_invalid
    server.start()
    try:
        sock = p2p.connect(server.address)
        try:
            invalid_blocked = request_fails(sock, {"type":"definitely_unknown"})
        finally:
            try: sock.close()
            except OSError: pass
        green(
            "cheap invalid message cannot bypass pre-dispatch rate gate",
            invalid_blocked and reject.calls and not invalid_handle_calls,
        )
    finally:
        server.stop()

    healthy = p2p.NodeServer(chain, None, host="127.0.0.1", port=0)
    healthy.start()
    try:
        sock = p2p.connect(healthy.address)
        try:
            replies = [p2p.request(sock, {"type":"get_status"}) for _ in range(4)]
        finally:
            sock.close()
        green(
            "healthy public request-reply traffic remains available",
            all(reply.get("type") == "status" for reply in replies),
        )
    finally:
        healthy.stop()

    direct = p2p.PeerSession(chain, None).handle({"type":"get_status"})
    green(
        "direct internal PeerSession dispatch remains unmetered",
        direct.get("type") == "status",
    )

    serve_src = inspect.getsource(p2p.serve_connection)
    server_src = inspect.getsource(p2p.NodeServer)
    green(
        "production listener meters every post-handshake message before PeerSession.handle",
        "message_gate is not None and not message_gate()" in serve_src
        and serve_src.index("message_gate is not None and not message_gate()")
            < serve_src.index("reply=session.handle")
        and "_message_rate_limiter=_InboundMessageRateLimiter()" in server_src
        and "message_gate=lambda: self._message_rate_limiter.consume" in server_src
        and "message_gate=message_gate" in server_src,
    )
    green(
        "SEC-123 response and SEC-122 frame budgets remain independently wired",
        "sync_response_byte_reserve=sync_response_byte_reserve" in serve_src
        and "frame_byte_budget=self._frame_byte_budget" in server_src
        and "_sync_response_byte_limiter" in server_src,
    )

    print(f"SEC-124 P2P message-rate budget: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
