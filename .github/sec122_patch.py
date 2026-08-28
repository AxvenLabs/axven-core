#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]


def read_lf(path):
    return (ROOT / path).read_bytes().decode("utf-8").replace("\r\n", "\n")


def write_lf(path, text):
    (ROOT / path).write_bytes(text.replace("\r\n", "\n").encode("utf-8"))


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"SEC-122 anchor {label!r} expected once, found {count}")
    return text.replace(old, new, 1)


p = read_lf("p2p.py")

p = replace_once(
    p,
    "MAX_OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_HOSTS = 1024\nMAX_P2P_MESSAGE_TYPE_CHARS = 32\n",
    "MAX_OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_HOSTS = 1024\n"
    "# A public peer can otherwise repeat tiny get_blocks requests and force\n"
    "# large response construction + egress at attacker-selected rates.  The\n"
    "# request gate bounds serialization frequency; the byte gate bounds wire\n"
    "# amplification.  These are local serving-policy budgets, not consensus.\n"
    "INBOUND_SYNC_RESPONSE_REQUEST_GLOBAL_RATE = 4.0\n"
    "INBOUND_SYNC_RESPONSE_REQUEST_GLOBAL_BURST = 8\n"
    "INBOUND_SYNC_RESPONSE_REQUEST_PER_HOST_RATE = 1.0\n"
    "INBOUND_SYNC_RESPONSE_REQUEST_PER_HOST_BURST = 4\n"
    "MAX_INBOUND_SYNC_RESPONSE_REQUEST_HOSTS = 1024\n"
    "INBOUND_SYNC_RESPONSE_BYTE_GLOBAL_RATE = 32 * 1024 * 1024\n"
    "INBOUND_SYNC_RESPONSE_BYTE_GLOBAL_BURST = MAX_MESSAGE_BYTES * 4\n"
    "INBOUND_SYNC_RESPONSE_BYTE_PER_HOST_RATE = 16 * 1024 * 1024\n"
    "INBOUND_SYNC_RESPONSE_BYTE_PER_HOST_BURST = MAX_MESSAGE_BYTES * 2\n"
    "MAX_INBOUND_SYNC_RESPONSE_BYTE_HOSTS = 1024\n"
    "MAX_P2P_MESSAGE_TYPE_CHARS = 32\n",
    "constants",
)

class_anchor = '''class _OutboundSyncBlockSignatureWorkLimiter(_InboundBlockSignatureWorkLimiter):
    """Persistent configured-peer weighted block-signature budget."""
    def __init__(
        self,
        clock=time.monotonic,
        global_rate=OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_GLOBAL_RATE,
        global_burst=OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_GLOBAL_BURST,
        per_host_rate=OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_PER_HOST_RATE,
        per_host_burst=OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_PER_HOST_BURST,
        max_hosts=MAX_OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_HOSTS,
    ):
        super().__init__(
            clock=clock, global_rate=global_rate, global_burst=global_burst,
            per_host_rate=per_host_rate, per_host_burst=per_host_burst,
            max_hosts=max_hosts,
        )


'''
class_replacement = class_anchor + '''class _InboundSyncResponseRequestLimiter(_InboundBlockWorkLimiter):
    """Bound public get_blocks response-build frequency."""
    def __init__(
        self,
        clock=time.monotonic,
        global_rate=INBOUND_SYNC_RESPONSE_REQUEST_GLOBAL_RATE,
        global_burst=INBOUND_SYNC_RESPONSE_REQUEST_GLOBAL_BURST,
        per_host_rate=INBOUND_SYNC_RESPONSE_REQUEST_PER_HOST_RATE,
        per_host_burst=INBOUND_SYNC_RESPONSE_REQUEST_PER_HOST_BURST,
        max_hosts=MAX_INBOUND_SYNC_RESPONSE_REQUEST_HOSTS,
    ):
        super().__init__(
            clock=clock, global_rate=global_rate, global_burst=global_burst,
            per_host_rate=per_host_rate, per_host_burst=per_host_burst,
            max_hosts=max_hosts,
        )


class _InboundSyncResponseByteLimiter(_InboundTxWorkLimiter):
    """Bound public get_blocks response bytes globally and per source."""
    def __init__(
        self,
        clock=time.monotonic,
        global_rate=INBOUND_SYNC_RESPONSE_BYTE_GLOBAL_RATE,
        global_burst=INBOUND_SYNC_RESPONSE_BYTE_GLOBAL_BURST,
        per_host_rate=INBOUND_SYNC_RESPONSE_BYTE_PER_HOST_RATE,
        per_host_burst=INBOUND_SYNC_RESPONSE_BYTE_PER_HOST_BURST,
        max_hosts=MAX_INBOUND_SYNC_RESPONSE_BYTE_HOSTS,
    ):
        super().__init__(
            clock=clock, global_rate=global_rate, global_burst=global_burst,
            per_host_rate=per_host_rate, per_host_burst=per_host_burst,
            max_hosts=max_hosts,
        )


'''
p = replace_once(p, class_anchor, class_replacement, "limiter classes")

p = replace_once(
    p,
    '''    def handle(
        self, msg, block_work_gate=None, tx_work_gate=None,
        block_signature_work_gate=None, stop_on_work_budget=False,
    ):
''',
    '''    def handle(
        self, msg, block_work_gate=None, tx_work_gate=None,
        block_signature_work_gate=None, stop_on_work_budget=False,
        sync_response_request_gate=None, sync_response_byte_gate=None,
    ):
''',
    "handle signature",
)

p = replace_once(
    p,
    '''            with self.chain._state_lock:
                start=0
''',
    '''            if (
                sync_response_request_gate is not None
                and not sync_response_request_gate()
            ):
                raise ProtocolError("sync response request budget exceeded")

            with self.chain._state_lock:
                start=0
''',
    "get_blocks request gate",
)

p = replace_once(
    p,
    '''                raw_blocks.append(raw_block)
                reply_size=candidate_size

            return {
                "type":"blocks",
                "blocks":raw_blocks,
            }
''',
    '''                raw_blocks.append(raw_block)
                reply_size=candidate_size

            if (
                sync_response_byte_gate is not None
                and not sync_response_byte_gate(reply_size)
            ):
                raise ProtocolError("sync response byte budget exceeded")

            return {
                "type":"blocks",
                "blocks":raw_blocks,
            }
''',
    "get_blocks byte gate",
)

p = replace_once(
    p,
    '''def serve_connection(
    sock, session:PeerSession, block_work_gate=None, tx_work_gate=None,
    block_signature_work_gate=None,
):
''',
    '''def serve_connection(
    sock, session:PeerSession, block_work_gate=None, tx_work_gate=None,
    block_signature_work_gate=None,
    sync_response_request_gate=None, sync_response_byte_gate=None,
):
''',
    "serve signature",
)

p = replace_once(
    p,
    '''            if tx_work_gate is not None or block_signature_work_gate is not None:
                reply=session.handle(
                    msg,
                    block_work_gate=block_work_gate,
                    tx_work_gate=tx_work_gate,
                    block_signature_work_gate=block_signature_work_gate,
                )
''',
    '''            if (
                tx_work_gate is not None
                or block_signature_work_gate is not None
                or sync_response_request_gate is not None
                or sync_response_byte_gate is not None
            ):
                reply=session.handle(
                    msg,
                    block_work_gate=block_work_gate,
                    tx_work_gate=tx_work_gate,
                    block_signature_work_gate=block_signature_work_gate,
                    sync_response_request_gate=sync_response_request_gate,
                    sync_response_byte_gate=sync_response_byte_gate,
                )
''',
    "serve handle wiring",
)

p = replace_once(
    p,
    '''        self._block_work_limiter=_InboundBlockWorkLimiter()
        self._tx_work_limiter=_InboundTxWorkLimiter()
        self._block_signature_work_limiter=_InboundBlockSignatureWorkLimiter()
''',
    '''        self._block_work_limiter=_InboundBlockWorkLimiter()
        self._tx_work_limiter=_InboundTxWorkLimiter()
        self._block_signature_work_limiter=_InboundBlockSignatureWorkLimiter()
        self._sync_response_request_limiter=_InboundSyncResponseRequestLimiter()
        self._sync_response_byte_limiter=_InboundSyncResponseByteLimiter()
''',
    "server limiters",
)

p = replace_once(
    p,
    '''                    block_signature_gate=lambda cost: (
                        self._block_signature_work_limiter.consume(source_host,cost)
                    )
                    try:
                        serve_connection(
                            client,self.session,
                            block_work_gate=block_gate,
                            tx_work_gate=tx_gate,
                            block_signature_work_gate=block_signature_gate,
                        )
''',
    '''                    block_signature_gate=lambda cost: (
                        self._block_signature_work_limiter.consume(source_host,cost)
                    )
                    sync_response_request_gate=lambda: (
                        self._sync_response_request_limiter.consume(source_host)
                    )
                    sync_response_byte_gate=lambda cost: (
                        self._sync_response_byte_limiter.consume(source_host,cost)
                    )
                    try:
                        serve_connection(
                            client,self.session,
                            block_work_gate=block_gate,
                            tx_work_gate=tx_gate,
                            block_signature_work_gate=block_signature_gate,
                            sync_response_request_gate=sync_response_request_gate,
                            sync_response_byte_gate=sync_response_byte_gate,
                        )
''',
    "server worker gates",
)

write_lf("p2p.py", p)

spec = r'''#!/usr/bin/env python3
"""SEC-122 bound public get_blocks response-build and egress amplification."""

import inspect
import axven
import p2p


class FakeClock:
    def __init__(self):
        self.now = 1000.0
    def __call__(self):
        return self.now
    def advance(self, seconds):
        self.now += seconds


def main():
    checks=[]
    def green(name, cond):
        assert cond, name
        checks.append(name)
        print("[GREEN]", name)

    green(
        "sync response budgets admit one max frame while bounding sustained serving",
        p2p.INBOUND_SYNC_RESPONSE_REQUEST_PER_HOST_BURST >= 1
        and 0 < p2p.INBOUND_SYNC_RESPONSE_REQUEST_PER_HOST_RATE
            < p2p.INBOUND_SYNC_RESPONSE_REQUEST_PER_HOST_BURST
        and p2p.INBOUND_SYNC_RESPONSE_BYTE_PER_HOST_BURST
            >= p2p.MAX_MESSAGE_BYTES
        and p2p.INBOUND_SYNC_RESPONSE_BYTE_GLOBAL_BURST
            >= 2 * p2p.MAX_MESSAGE_BYTES,
    )

    clock=FakeClock()
    req=p2p._InboundSyncResponseRequestLimiter(
        clock=clock, global_rate=1, global_burst=2,
        per_host_rate=1, per_host_burst=2, max_hosts=2,
    )
    green(
        "single source cannot spam response construction beyond request burst",
        req.consume("192.0.2.1") and req.consume("192.0.2.1")
        and not req.consume("192.0.2.1"),
    )
    clock.advance(1.0)
    green(
        "sync response request budget refills at configured rate",
        req.consume("192.0.2.1"),
    )

    dist=p2p._InboundSyncResponseRequestLimiter(
        clock=FakeClock(), global_rate=1, global_burst=2,
        per_host_rate=1, per_host_burst=2, max_hosts=2,
    )
    green(
        "distributed sources remain globally bounded for response builds",
        dist.consume("192.0.2.1") and dist.consume("192.0.2.2")
        and not dist.consume("192.0.2.3"),
    )
    dist.consume("192.0.2.3")
    green(
        "sync response limiter source memory is bounded",
        dist.snapshot()["hosts"] <= 2,
    )

    byte_clock=FakeClock()
    byte_limiter=p2p._InboundSyncResponseByteLimiter(
        clock=byte_clock, global_rate=8, global_burst=16,
        per_host_rate=4, per_host_burst=10, max_hosts=2,
    )
    green(
        "response bytes are charged by actual serialized cost",
        byte_limiter.consume("198.51.100.1", 8)
        and not byte_limiter.consume("198.51.100.1", 3),
    )
    byte_clock.advance(1.0)
    green(
        "response byte budget refills without reconnect reset",
        byte_limiter.consume("198.51.100.1", 3),
    )

    miner=axven.Wallet()
    chain=axven.Blockchain()
    for _ in range(3):
        chain.mine(miner.address)
    session=p2p.PeerSession(chain, None)
    msg={
        "type":"get_blocks",
        "locator":[chain.blocks[0].hash()],
        "limit":2,
    }
    gate_calls=[]
    reply=session.handle(
        msg,
        sync_response_request_gate=lambda: gate_calls.append("request") or True,
        sync_response_byte_gate=lambda cost: gate_calls.append(("bytes",cost)) or True,
    )
    green(
        "healthy bounded get_blocks response preserves forward sync semantics",
        reply["type"] == "blocks" and len(reply["blocks"]) == 2
        and gate_calls[0] == "request"
        and gate_calls[1] == ("bytes", len(p2p._json_bytes(reply))),
    )

    original_json=p2p._json_bytes
    json_calls=[]
    def trap_json(value):
        json_calls.append(value)
        raise AssertionError("serialization reached after exhausted request gate")
    p2p._json_bytes=trap_json
    try:
        try:
            session.handle(msg, sync_response_request_gate=lambda: False)
            request_blocked=False
        except p2p.ProtocolError as exc:
            request_blocked=("request budget exceeded" in str(exc))
    finally:
        p2p._json_bytes=original_json
    green(
        "exhausted request budget stops before response serialization",
        request_blocked and not json_calls,
    )

    byte_cost=[]
    try:
        session.handle(
            msg,
            sync_response_request_gate=lambda: True,
            sync_response_byte_gate=lambda cost: byte_cost.append(cost) or False,
        )
        byte_blocked=False
    except p2p.ProtocolError as exc:
        byte_blocked=("byte budget exceeded" in str(exc))
    green(
        "exhausted byte budget stops the oversized response before send",
        byte_blocked and byte_cost
        and 0 < byte_cost[0] <= p2p.MAX_MESSAGE_BYTES,
    )

    plain=session.handle(msg)
    green(
        "unmetered direct session behavior remains compatible",
        plain["type"] == "blocks" and len(plain["blocks"]) == 2,
    )

    # Network wiring: one request token, then the same connection is closed;
    # after refill a reconnect can make progress again.
    public_chain=axven.Blockchain()
    for _ in range(2):
        public_chain.mine(miner.address)
    server=p2p.NodeServer(public_chain, None, host="127.0.0.1", port=0)
    net_clock=FakeClock()
    server._sync_response_request_limiter=p2p._InboundSyncResponseRequestLimiter(
        clock=net_clock, global_rate=1, global_burst=1,
        per_host_rate=1, per_host_burst=1, max_hosts=2,
    )
    server._sync_response_byte_limiter=p2p._InboundSyncResponseByteLimiter(
        clock=net_clock, global_rate=p2p.MAX_MESSAGE_BYTES,
        global_burst=p2p.MAX_MESSAGE_BYTES,
        per_host_rate=p2p.MAX_MESSAGE_BYTES,
        per_host_burst=p2p.MAX_MESSAGE_BYTES,
        max_hosts=2,
    )
    server.start()
    try:
        sock=p2p.connect(server.address)
        try:
            first=p2p.request(sock,{"type":"get_blocks","locator":[],"limit":1})
            try:
                p2p.request(sock,{"type":"get_blocks","locator":[],"limit":1})
                throttled=False
            except (EOFError,OSError,p2p.ProtocolError):
                throttled=True
        finally:
            try: sock.close()
            except OSError: pass
        green(
            "public listener closes repeated get_blocks serving at request budget edge",
            first.get("type") == "blocks" and throttled,
        )
        net_clock.advance(1.0)
        sock2=p2p.connect(server.address)
        try:
            resumed=p2p.request(sock2,{"type":"get_blocks","locator":[],"limit":1})
        finally:
            sock2.close()
        green(
            "refilled public response budget allows reconnect progress",
            resumed.get("type") == "blocks" and len(resumed.get("blocks",[])) == 1,
        )
    finally:
        server.stop()

    handle_src=inspect.getsource(p2p.PeerSession.handle)
    serve_src=inspect.getsource(p2p.serve_connection)
    server_src=inspect.getsource(p2p.NodeServer)
    green(
        "production wiring gates get_blocks before build and before send",
        "sync_response_request_gate" in handle_src
        and "sync response request budget exceeded" in handle_src
        and "sync_response_byte_gate(reply_size)" in handle_src
        and "sync response byte budget exceeded" in handle_src
        and "sync_response_request_gate=sync_response_request_gate" in serve_src
        and "sync_response_byte_gate=sync_response_byte_gate" in serve_src
        and "_sync_response_request_limiter" in server_src
        and "_sync_response_byte_limiter" in server_src,
    )

    print(f"SEC-122 get_blocks response budget: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
'''
write_lf("security_sec122_get_blocks_response_budget_spec.py", spec)

# Normalize changed production/spec bytes before hashing so Git's LF-normalized
# committed blobs exactly match release_manifest on Windows runners.
for name in ("p2p.py", "security_sec122_get_blocks_response_budget_spec.py"):
    data=(ROOT / name).read_bytes().replace(b"\r\n", b"\n")
    (ROOT / name).write_bytes(data)

manifest_path=ROOT / "release_manifest.json"
manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
for name in ("p2p.py", "security_sec122_get_blocks_response_budget_spec.py"):
    data=(ROOT / name).read_bytes()
    manifest["files"][name]={
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest_text=json.dumps(manifest, indent=2, sort_keys=True) + "\n"
manifest_path.write_bytes(manifest_text.encode("utf-8"))
print("SEC-122 patch applied")
