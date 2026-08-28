from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
P2P = ROOT / "p2p.py"
SPEC = ROOT / "security_sec124_p2p_message_rate_budget_spec.py"
MANIFEST = ROOT / "release_manifest.json"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"SEC-124 patch anchor {label!r}: expected 1, found {count}")
    return text.replace(old, new, 1)


text = P2P.read_text(encoding="utf-8").replace("\r\n", "\n")

text = replace_once(
    text,
    "MAX_INBOUND_SYNC_RESPONSE_BYTE_HOSTS = 1024\nMAX_P2P_MESSAGE_TYPE_CHARS = 32\n",
    "MAX_INBOUND_SYNC_RESPONSE_BYTE_HOSTS = 1024\n"
    "# Even cheap post-handshake messages still consume JSON/dispatch/lock/reply\n"
    "# work. Bound their aggregate rate independently from the heavier block, TX,\n"
    "# signature, frame-lifetime, and sync-response budgets. Listener ownership\n"
    "# keeps source buckets alive across reconnects. Transport policy only.\n"
    "INBOUND_MESSAGE_GLOBAL_RATE = 512.0\n"
    "INBOUND_MESSAGE_GLOBAL_BURST = 2048\n"
    "INBOUND_MESSAGE_PER_HOST_RATE = 128.0\n"
    "INBOUND_MESSAGE_PER_HOST_BURST = 256\n"
    "MAX_INBOUND_MESSAGE_HOSTS = 1024\n"
    "MAX_P2P_MESSAGE_TYPE_CHARS = 32\n",
    "message constants",
)

message_limiter = '''class _InboundMessageRateLimiter(_InboundBlockWorkLimiter):
    """Persistent global + source budget for post-handshake dispatch rate."""
    def __init__(
        self,
        clock=time.monotonic,
        global_rate=INBOUND_MESSAGE_GLOBAL_RATE,
        global_burst=INBOUND_MESSAGE_GLOBAL_BURST,
        per_host_rate=INBOUND_MESSAGE_PER_HOST_RATE,
        per_host_burst=INBOUND_MESSAGE_PER_HOST_BURST,
        max_hosts=MAX_INBOUND_MESSAGE_HOSTS,
    ):
        super().__init__(
            clock=clock, global_rate=global_rate, global_burst=global_burst,
            per_host_rate=per_host_rate, per_host_burst=per_host_burst,
            max_hosts=max_hosts,
        )


'''
text = replace_once(
    text,
    "class _SyncResponseByteLease:\n",
    message_limiter + "class _SyncResponseByteLease:\n",
    "message limiter class",
)

text = replace_once(
    text,
    "def serve_connection(\n    sock, session:PeerSession, block_work_gate=None, tx_work_gate=None,\n    block_signature_work_gate=None, frame_byte_budget=None,\n    sync_response_byte_reserve=None,\n):\n",
    "def serve_connection(\n    sock, session:PeerSession, block_work_gate=None, tx_work_gate=None,\n    block_signature_work_gate=None, frame_byte_budget=None,\n    sync_response_byte_reserve=None, message_gate=None,\n):\n",
    "serve signature",
)

text = replace_once(
    text,
    "                sock.settimeout(INBOUND_PEER_TIMEOUT)\n                if (\n",
    "                sock.settimeout(INBOUND_PEER_TIMEOUT)\n"
    "                if message_gate is not None and not message_gate():\n"
    "                    raise ProtocolError(\"inbound message rate exceeded\")\n"
    "                if (\n",
    "pre-dispatch gate",
)

text = replace_once(
    text,
    "        self._block_signature_work_limiter=_InboundBlockSignatureWorkLimiter()\n        self._frame_byte_budget=_InboundFrameByteBudget()\n",
    "        self._block_signature_work_limiter=_InboundBlockSignatureWorkLimiter()\n"
    "        self._message_rate_limiter=_InboundMessageRateLimiter()\n"
    "        self._frame_byte_budget=_InboundFrameByteBudget()\n",
    "server limiter ownership",
)

text = replace_once(
    text,
    "                    sync_response_byte_reserve=lambda cost: (\n                        self._sync_response_byte_limiter.reserve(source_host,cost)\n                    )\n                    try:\n",
    "                    sync_response_byte_reserve=lambda cost: (\n"
    "                        self._sync_response_byte_limiter.reserve(source_host,cost)\n"
    "                    )\n"
    "                    message_gate=lambda: self._message_rate_limiter.consume(\n"
    "                        source_host\n"
    "                    )\n"
    "                    try:\n",
    "worker gate",
)

text = replace_once(
    text,
    "                            sync_response_byte_reserve=sync_response_byte_reserve,\n                        )\n",
    "                            sync_response_byte_reserve=sync_response_byte_reserve,\n"
    "                            message_gate=message_gate,\n"
    "                        )\n",
    "serve wiring",
)

P2P.write_text(text, encoding="utf-8", newline="\n")

spec = r'''#!/usr/bin/env python3
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
'''
SPEC.write_text(spec.replace("\r\n", "\n"), encoding="utf-8", newline="\n")

manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
for path in (P2P, SPEC):
    raw = path.read_bytes().replace(b"\r\n", b"\n")
    path.write_bytes(raw)
    manifest["files"][path.name] = {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
MANIFEST.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)

print("SEC-124 patch applied")
