#!/usr/bin/env python3
"""SEC-133 bound public pre-auth handshake worker churn across reconnects."""

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


def client_count(server):
    with server._lock:
        return len(server._clients)


def connect_fails(address):
    try:
        sock = p2p.connect(address, timeout=1.0)
    except (EOFError, OSError, p2p.ProtocolError):
        return True
    else:
        sock.close()
        return False


def main():
    checks = []
    def green(name, cond):
        assert cond, name
        checks.append(name)
        print("[GREEN]", name)

    green(
        "handshake admission budgets are generous over concurrent peer quotas",
        p2p.INBOUND_HANDSHAKE_GLOBAL_RATE == 64.0
        and p2p.INBOUND_HANDSHAKE_GLOBAL_BURST == 128
        and p2p.INBOUND_HANDSHAKE_PER_HOST_RATE == 8.0
        and p2p.INBOUND_HANDSHAKE_PER_HOST_BURST == 16
        and p2p.MAX_INBOUND_HANDSHAKE_HOSTS == 1024
        and p2p.INBOUND_HANDSHAKE_GLOBAL_BURST >= 4 * p2p.MAX_INBOUND_PEERS
        and p2p.INBOUND_HANDSHAKE_PER_HOST_BURST >= 4 * p2p.MAX_INBOUND_PEERS_PER_HOST,
    )

    clock = FakeClock()
    limiter = p2p._InboundHandshakeRateLimiter(
        clock=clock, global_rate=8, global_burst=8,
        per_host_rate=2, per_host_burst=3, max_hosts=4,
    )
    green(
        "single source pre-auth burst is bounded",
        all(limiter.consume("192.0.2.1") for _ in range(3))
        and not limiter.consume("192.0.2.1"),
    )
    clock.advance(0.5)
    green(
        "single source handshake budget refills at configured rate",
        limiter.consume("192.0.2.1"),
    )

    global_limiter = p2p._InboundHandshakeRateLimiter(
        clock=FakeClock(), global_rate=1, global_burst=2,
        per_host_rate=10, per_host_burst=10, max_hosts=4,
    )
    green(
        "distributed sources remain globally handshake-rate bounded",
        global_limiter.consume("198.51.100.1")
        and global_limiter.consume("198.51.100.2")
        and not global_limiter.consume("198.51.100.3"),
    )

    bounded = p2p._InboundHandshakeRateLimiter(
        clock=FakeClock(), global_rate=100, global_burst=100,
        per_host_rate=100, per_host_burst=100, max_hosts=2,
    )
    for i in range(8):
        assert bounded.consume(f"203.0.113.{i+1}")
    green(
        "handshake limiter source memory is bounded",
        bounded.snapshot()["hosts"] <= 2,
    )

    chain = axven.Blockchain()
    reconnect_clock = FakeClock()
    reconnect_limiter = p2p._InboundHandshakeRateLimiter(
        clock=reconnect_clock, global_rate=0.001, global_burst=8,
        per_host_rate=0.001, per_host_burst=1, max_hosts=8,
    )
    server = p2p.NodeServer(chain, None, host="127.0.0.1", port=0)
    server._handshake_rate_limiter = reconnect_limiter
    server.start()
    try:
        first = p2p.connect(server.address, timeout=1.0)
        first.close()
        green(
            "first admitted handshake completes normally",
            wait_for(lambda: client_count(server) == 0),
        )
        green(
            "socket reconnect cannot mint a fresh same-host handshake burst",
            connect_fails(server.address),
        )
        reconnect_clock.advance(1000.0)
        third = p2p.connect(server.address, timeout=1.0)
        third.close()
        green(
            "refilled listener-owned handshake budget permits reconnect recovery",
            wait_for(lambda: client_count(server) == 0),
        )
    finally:
        server.stop()

    # An exhausted admission gate must reject before client registration and
    # before a worker can run server-sent hello/JSON handshake work.
    reject = RejectLimiter()
    server = p2p.NodeServer(chain, None, host="127.0.0.1", port=0)
    server._handshake_rate_limiter = reject
    serve_calls = []
    original_serve = p2p.serve_connection
    def trap_serve(*args, **kwargs):
        serve_calls.append(1)
        return original_serve(*args, **kwargs)
    p2p.serve_connection = trap_serve
    server.start()
    raw = None
    try:
        raw = socket.create_connection(server.address, timeout=1.0)
        raw.settimeout(1.0)
        green(
            "exhausted admission is consulted for the kernel-derived source host",
            wait_for(lambda: bool(reject.calls))
            and reject.calls[-1] == "127.0.0.1",
        )
        green(
            "admission rejection occurs before worker spawn and client retention",
            wait_for(lambda: client_count(server) == 0)
            and not serve_calls,
        )
    finally:
        if raw is not None:
            try: raw.close()
            except OSError: pass
        server.stop()
        p2p.serve_connection = original_serve

    healthy = p2p.NodeServer(chain, None, host="127.0.0.1", port=0)
    healthy.start()
    try:
        sock = p2p.connect(healthy.address, timeout=1.0)
        try:
            reply = p2p.request(sock, {"type":"get_status"})
        finally:
            sock.close()
        green(
            "healthy handshake and post-handshake request remain available",
            reply.get("type") == "status",
        )
    finally:
        healthy.stop()

    server_src = inspect.getsource(p2p.NodeServer)
    green(
        "concurrent SEC-105 quotas stay ahead of rate-token consumption",
        server_src.index("len(self._clients) >= MAX_INBOUND_PEERS")
        < server_src.index("_handshake_rate_limiter.consume(remote_host)")
        < server_src.index("self._clients.add(c)"),
    )
    green(
        "production admission gate runs before handshake worker creation",
        server_src.index("_handshake_rate_limiter.consume(remote_host)")
        < server_src.index("threading.Thread(target=worker,daemon=True).start()"),
    )
    green(
        "listener owns both pre-auth and post-handshake persistent rate budgets",
        "self._handshake_rate_limiter=_InboundHandshakeRateLimiter()" in server_src
        and "self._message_rate_limiter=_InboundMessageRateLimiter()" in server_src,
    )
    green(
        "handshake admission hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-133 P2P handshake admission rate: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
