#!/usr/bin/env python3
"""SEC-220 bound inbound P2P raw-byte parsing throughput."""

import hashlib
import inspect
import json
import socket
import struct
import time
from pathlib import Path

import axven
import p2p


ROOT = Path(__file__).resolve().parent


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class RejectParseGate:
    def __init__(self):
        self.costs = []

    def __call__(self, cost):
        self.costs.append(cost)
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


def file_record(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def main():
    checks = []

    def green(name, cond):
        assert cond, name
        checks.append(name)
        print("[GREEN]", name)

    green(
        "parse-byte policy admits at least one legal maximum frame from a fresh source",
        p2p.INBOUND_PARSE_BYTE_PER_HOST_BURST >= p2p.MAX_MESSAGE_BYTES
        and p2p.INBOUND_PARSE_BYTE_GLOBAL_BURST >= p2p.INBOUND_PARSE_BYTE_PER_HOST_BURST
        and 0 < p2p.INBOUND_PARSE_BYTE_PER_HOST_RATE < p2p.INBOUND_PARSE_BYTE_PER_HOST_BURST
        and 0 < p2p.INBOUND_PARSE_BYTE_GLOBAL_RATE < p2p.INBOUND_PARSE_BYTE_GLOBAL_BURST,
    )

    clock = FakeClock()
    limiter = p2p._InboundParseByteLimiter(
        clock=clock,
        global_rate=20,
        global_burst=40,
        per_host_rate=10,
        per_host_burst=20,
        max_hosts=4,
    )
    green(
        "single source is bounded by weighted raw frame bytes rather than message count",
        limiter.consume("192.0.2.1", 12)
        and limiter.consume("192.0.2.1", 8)
        and not limiter.consume("192.0.2.1", 1),
    )
    clock.advance(0.5)
    green(
        "parse-byte source budget refills at the pinned byte rate",
        limiter.consume("192.0.2.1", 5)
        and not limiter.consume("192.0.2.1", 1),
    )

    global_clock = FakeClock()
    global_limit = p2p._InboundParseByteLimiter(
        clock=global_clock,
        global_rate=1,
        global_burst=10,
        per_host_rate=100,
        per_host_burst=100,
        max_hosts=8,
    )
    green(
        "distributed sources remain globally parse-byte bounded",
        global_limit.consume("198.51.100.1", 6)
        and global_limit.consume("198.51.100.2", 4)
        and not global_limit.consume("198.51.100.3", 1),
    )

    bounded_hosts = p2p._InboundParseByteLimiter(
        clock=FakeClock(),
        global_rate=1000,
        global_burst=1000,
        per_host_rate=100,
        per_host_burst=100,
        max_hosts=2,
    )
    for i in range(8):
        assert bounded_hosts.consume(f"203.0.113.{i + 1}", 1)
    green(
        "parse-byte limiter source memory is independently bounded",
        bounded_hosts.snapshot()["hosts"] <= 2,
    )

    # The SEC-220 gate deliberately runs only after the declared body is fully
    # received. Charging the 4-byte length prefix would let a peer consume a
    # 16 MiB global token reservation by sending only four bytes and stalling.
    left, right = socket.socketpair()
    prefix_gate_calls = []
    try:
        right.sendall(struct.pack(">I", 32))
        right.shutdown(socket.SHUT_WR)
        try:
            p2p._recv_message_with_lease(
                left,
                frame_byte_budget=p2p._InboundFrameByteBudget(),
                parse_byte_gate=lambda cost: prefix_gate_calls.append(cost) or True,
            )
        except EOFError:
            pass
        else:
            raise AssertionError("truncated frame unexpectedly accepted")
    finally:
        left.close()
        right.close()
    green(
        "declared-length-only peer cannot spend parse-byte tokens",
        prefix_gate_calls == [],
    )

    # Once a complete body exists, exhausted byte capacity must stop before the
    # O(n) structural preflight and json.loads allocation. The SEC-122 lifetime
    # lease must still be released on this new rejection path.
    raw = b'{"type":"get_status"}'
    left, right = socket.socketpair()
    reject_gate = RejectParseGate()
    budget = p2p._InboundFrameByteBudget()
    preflight_calls = []
    original_preflight = p2p._preflight_json_nesting
    original_loads = p2p.json.loads

    def trap_preflight(*args, **kwargs):
        preflight_calls.append(True)
        return original_preflight(*args, **kwargs)

    loads_calls = []

    def trap_loads(*args, **kwargs):
        loads_calls.append(True)
        return original_loads(*args, **kwargs)

    p2p._preflight_json_nesting = trap_preflight
    p2p.json.loads = trap_loads
    try:
        right.sendall(struct.pack(">I", len(raw)) + raw)
        try:
            p2p._recv_message_with_lease(
                left,
                frame_byte_budget=budget,
                parse_byte_gate=reject_gate,
            )
        except p2p.ProtocolError as exc:
            blocked = str(exc) == "inbound parse byte budget exceeded"
        else:
            blocked = False
    finally:
        p2p._preflight_json_nesting = original_preflight
        p2p.json.loads = original_loads
        left.close()
        right.close()
    green(
        "exhausted parse-byte gate runs after body receive but before preflight and json decode",
        blocked
        and reject_gate.costs == [len(raw)]
        and preflight_calls == []
        and loads_calls == [],
    )
    green(
        "parse-byte rejection releases SEC-122 frame lifetime reservation",
        budget.snapshot()["inflight_bytes"] == 0,
    )

    wallet = axven.Wallet()
    chain = axven.Blockchain()
    chain.mine(wallet.address)

    # Listener-owned state must survive reconnects. A worker-local limiter would
    # let a hostile source mint a fresh byte burst for every TCP connection.
    request_bytes = len(p2p._json_bytes({"type": "get_status"}))
    reconnect_limiter = p2p._InboundParseByteLimiter(
        clock=FakeClock(),
        global_rate=0.001,
        global_burst=request_bytes * 4,
        per_host_rate=0.001,
        per_host_burst=request_bytes,
        max_hosts=8,
    )
    server = p2p.NodeServer(chain, None, host="127.0.0.1", port=0)
    server._parse_byte_limiter = reconnect_limiter
    server.start()
    try:
        first = p2p.connect(server.address)
        try:
            first_reply = p2p.request(first, {"type": "get_status"})
        finally:
            first.close()
        second = p2p.connect(server.address)
        try:
            second_blocked = request_fails(second, {"type": "get_status"})
        finally:
            try:
                second.close()
            except OSError:
                pass
        green(
            "socket reconnect does not reset same-host parse-byte budget",
            first_reply.get("type") == "status" and second_blocked,
        )
    finally:
        server.stop()

    healthy = p2p.NodeServer(chain, None, host="127.0.0.1", port=0)
    healthy.start()
    try:
        sock = p2p.connect(healthy.address)
        try:
            replies = [p2p.request(sock, {"type": "get_status"}) for _ in range(4)]
        finally:
            sock.close()
        green(
            "healthy public request-reply traffic remains available",
            all(reply.get("type") == "status" for reply in replies),
        )
    finally:
        healthy.stop()

    recv_src = inspect.getsource(p2p._recv_message_with_lease)
    serve_src = inspect.getsource(p2p.serve_connection)
    server_src = inspect.getsource(p2p.NodeServer)
    green(
        "production parser charges exact body bytes before structural scan and json.loads",
        "parse_byte_gate is not None and not parse_byte_gate(n)" in recv_src
        and recv_src.index("parse_byte_gate is not None and not parse_byte_gate(n)")
        < recv_src.index("_preflight_json_nesting(raw)")
        < recv_src.index("json.loads"),
    )
    green(
        "listener owns persistent parse-byte limiter and wires it to every post-handshake frame",
        "_parse_byte_limiter=_InboundParseByteLimiter()" in server_src
        and "parse_byte_gate=lambda cost: self._parse_byte_limiter.consume" in server_src
        and "parse_byte_gate=parse_byte_gate" in server_src
        and "parse_byte_gate=parse_byte_gate" in serve_src,
    )
    green(
        "SEC-122 frame lifetime and SEC-124 dispatch-rate gates remain independently wired",
        "frame_byte_budget=self._frame_byte_budget" in server_src
        and "message_gate=message_gate" in server_src
        and "inbound message rate exceeded" in serve_src,
    )

    manifest = json.loads((ROOT / "release_manifest.json").read_text(encoding="utf-8"))
    expected_files = manifest["files"]
    green(
        "release manifest authenticates SEC-220 production and regression bytes",
        expected_files.get("p2p.py") == file_record(ROOT / "p2p.py")
        and expected_files.get(Path(__file__).name) == file_record(Path(__file__)),
    )
    green(
        "canonical chain and protocol identity remain unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and p2p.PROTOCOL_VERSION == 3,
    )

    print(f"SEC-220 P2P parse-byte budget: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
