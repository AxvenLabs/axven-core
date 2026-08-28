#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json

ROOT=Path(__file__).resolve().parents[1]


def read_lf(name):
    return (ROOT/name).read_bytes().decode("utf-8").replace("\r\n","\n")


def write_lf(name,text):
    (ROOT/name).write_bytes(text.replace("\r\n","\n").encode("utf-8"))


def replace_once(text,old,new,label):
    count=text.count(old)
    if count != 1:
        raise SystemExit(f"SEC-123 anchor {label!r}: expected 1, found {count}")
    return text.replace(old,new,1)


p=read_lf("p2p.py")

p=replace_once(
    p,
    "MAX_OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_HOSTS = 1024\nMAX_P2P_MESSAGE_TYPE_CHARS = 32\n",
    "MAX_OUTBOUND_SYNC_BLOCK_SIGNATURE_WORK_HOSTS = 1024\n"
    "# Public get_blocks can otherwise make a peer repeatedly build and send\n"
    "# near-16 MiB responses at attacker-selected rates. Reserve one maximum\n"
    "# response before serialization and refund the unused portion after the\n"
    "# exact response size is known. This is local serving policy only.\n"
    "INBOUND_SYNC_RESPONSE_BYTE_GLOBAL_RATE = 64 * 1024 * 1024\n"
    "INBOUND_SYNC_RESPONSE_BYTE_GLOBAL_BURST = 128 * 1024 * 1024\n"
    "INBOUND_SYNC_RESPONSE_BYTE_PER_HOST_RATE = 16 * 1024 * 1024\n"
    "INBOUND_SYNC_RESPONSE_BYTE_PER_HOST_BURST = 64 * 1024 * 1024\n"
    "MAX_INBOUND_SYNC_RESPONSE_BYTE_HOSTS = 1024\n"
    "MAX_P2P_MESSAGE_TYPE_CHARS = 32\n",
    "constants",
)

class_anchor='''class _OutboundSyncBlockSignatureWorkLimiter(_InboundBlockSignatureWorkLimiter):
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
class_add=class_anchor+'''class _SyncResponseByteLease:
    """Reservation that leaves only actual serialized bytes charged."""
    def __init__(self,budget,host,reserved):
        self._budget=budget
        self._host=host
        self._reserved=reserved
        self._finished=False

    def settle(self,actual_bytes):
        if self._finished:
            return
        if (
            type(actual_bytes) is not int
            or actual_bytes <= 0
            or actual_bytes > self._reserved
        ):
            raise ValueError("invalid sync response byte settlement")
        self._finished=True
        unused=self._reserved-actual_bytes
        if unused:
            self._budget._refund(self._host,unused)

    def cancel(self):
        if self._finished:
            return
        self._finished=True
        self._budget._refund(self._host,self._reserved)


class _InboundSyncResponseByteLimiter(_InboundTxWorkLimiter):
    """Persistent global + source byte budget for public sync responses."""
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

    def reserve(self,host,size=MAX_MESSAGE_BYTES):
        if type(size) is not int or size <= 0 or size > MAX_MESSAGE_BYTES:
            return None
        if not self.consume(host,size):
            return None
        return _SyncResponseByteLease(self,host,size)

    def _refund(self,host,cost):
        if type(cost) is not int or cost < 0:
            raise ValueError("invalid sync response byte refund")
        if cost == 0:
            return
        now=float(self._clock())
        with self._lock:
            global_tokens=self._refill(
                self._global_tokens,self._global_last,now,
                self._global_rate,self._global_burst,
            )
            self._global_tokens=min(self._global_burst,global_tokens+cost)
            self._global_last=now

            entry=self._hosts.get(host)
            if entry is None:
                # A live reservation normally keeps its source entry hot. If
                # an adversarial source churn evicted it, do not recreate a
                # fresh per-host bucket while refunding; global accounting is
                # still restored without minting source capacity.
                return
            host_tokens,host_last=entry
            host_tokens=self._refill(
                host_tokens,host_last,now,
                self._per_host_rate,self._per_host_burst,
            )
            host_tokens=min(self._per_host_burst,host_tokens+cost)
            self._hosts[host]=(host_tokens,now)
            self._hosts.move_to_end(host)


'''
p=replace_once(p,class_anchor,class_add,"response limiter classes")

p=replace_once(
    p,
    '''    def handle(
        self, msg, block_work_gate=None, tx_work_gate=None,
        block_signature_work_gate=None, stop_on_work_budget=False,
    ):
''',
    '''    def handle(
        self, msg, block_work_gate=None, tx_work_gate=None,
        block_signature_work_gate=None, stop_on_work_budget=False,
        sync_response_byte_reserve=None,
    ):
''',
    "handle signature",
)

old_get='''            with self.chain._state_lock:
                start=0
                for h in locator:
                    node=self.chain.index.get(h)
                    if node is None:
                        continue
                    height=node.height
                    if (
                        0 <= height < len(self.chain.blocks)
                        and self.chain.blocks[height].hash() == h
                    ):
                        start=height+1
                        break
                blocks=list(
                    self.chain.blocks[
                        start:start+limit
                    ]
                )

            raw_blocks=[]
            reply_size=len(_json_bytes({"type":"blocks","blocks":[]}))
            for block in blocks:
                raw_block=block.to_dict()
                raw_block_size=len(_json_bytes(raw_block))
                candidate_size=(
                    reply_size
                    + raw_block_size
                    + (1 if raw_blocks else 0)
                )
                if candidate_size>MAX_MESSAGE_BYTES:
                    break
                raw_blocks.append(raw_block)
                reply_size=candidate_size

            return {
                "type":"blocks",
                "blocks":raw_blocks,
            }
'''
new_get='''            response_lease=None
            if sync_response_byte_reserve is not None:
                response_lease=sync_response_byte_reserve(MAX_MESSAGE_BYTES)
                if response_lease is None:
                    raise ProtocolError("sync response byte budget exceeded")

            try:
                with self.chain._state_lock:
                    start=0
                    for h in locator:
                        node=self.chain.index.get(h)
                        if node is None:
                            continue
                        height=node.height
                        if (
                            0 <= height < len(self.chain.blocks)
                            and self.chain.blocks[height].hash() == h
                        ):
                            start=height+1
                            break
                    blocks=list(
                        self.chain.blocks[
                            start:start+limit
                        ]
                    )

                raw_blocks=[]
                reply_size=len(_json_bytes({"type":"blocks","blocks":[]}))
                for block in blocks:
                    raw_block=block.to_dict()
                    raw_block_size=len(_json_bytes(raw_block))
                    candidate_size=(
                        reply_size
                        + raw_block_size
                        + (1 if raw_blocks else 0)
                    )
                    if candidate_size>MAX_MESSAGE_BYTES:
                        break
                    raw_blocks.append(raw_block)
                    reply_size=candidate_size

                reply={
                    "type":"blocks",
                    "blocks":raw_blocks,
                }
                if response_lease is not None:
                    response_lease.settle(reply_size)
                return reply
            except Exception:
                if response_lease is not None:
                    response_lease.cancel()
                raise
'''
p=replace_once(p,old_get,new_get,"get_blocks reservation")

p=replace_once(
    p,
    '''def serve_connection(
    sock, session:PeerSession, block_work_gate=None, tx_work_gate=None,
    block_signature_work_gate=None, frame_byte_budget=None,
):
''',
    '''def serve_connection(
    sock, session:PeerSession, block_work_gate=None, tx_work_gate=None,
    block_signature_work_gate=None, frame_byte_budget=None,
    sync_response_byte_reserve=None,
):
''',
    "serve signature",
)

p=replace_once(
    p,
    '''                if tx_work_gate is not None or block_signature_work_gate is not None:
                    reply=session.handle(
                        msg,
                        block_work_gate=block_work_gate,
                        tx_work_gate=tx_work_gate,
                        block_signature_work_gate=block_signature_work_gate,
                    )
''',
    '''                if (
                    tx_work_gate is not None
                    or block_signature_work_gate is not None
                    or sync_response_byte_reserve is not None
                ):
                    reply=session.handle(
                        msg,
                        block_work_gate=block_work_gate,
                        tx_work_gate=tx_work_gate,
                        block_signature_work_gate=block_signature_work_gate,
                        sync_response_byte_reserve=sync_response_byte_reserve,
                    )
''',
    "serve session wiring",
)

p=replace_once(
    p,
    '''        self._block_signature_work_limiter=_InboundBlockSignatureWorkLimiter()
        self._frame_byte_budget=_InboundFrameByteBudget()
''',
    '''        self._block_signature_work_limiter=_InboundBlockSignatureWorkLimiter()
        self._frame_byte_budget=_InboundFrameByteBudget()
        self._sync_response_byte_limiter=_InboundSyncResponseByteLimiter()
''',
    "server limiter",
)

p=replace_once(
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
                            frame_byte_budget=self._frame_byte_budget,
                        )
''',
    '''                    block_signature_gate=lambda cost: (
                        self._block_signature_work_limiter.consume(source_host,cost)
                    )
                    sync_response_byte_reserve=lambda cost: (
                        self._sync_response_byte_limiter.reserve(source_host,cost)
                    )
                    try:
                        serve_connection(
                            client,self.session,
                            block_work_gate=block_gate,
                            tx_work_gate=tx_gate,
                            block_signature_work_gate=block_signature_gate,
                            frame_byte_budget=self._frame_byte_budget,
                            sync_response_byte_reserve=sync_response_byte_reserve,
                        )
''',
    "server worker wiring",
)

write_lf("p2p.py",p)

spec=r'''#!/usr/bin/env python3
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
'''
write_lf("security_sec123_get_blocks_response_budget_spec.py",spec)

for name in ("p2p.py","security_sec123_get_blocks_response_budget_spec.py"):
    data=(ROOT/name).read_bytes().replace(b"\r\n",b"\n")
    (ROOT/name).write_bytes(data)

manifest_path=ROOT/"release_manifest.json"
manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
for name in ("p2p.py","security_sec123_get_blocks_response_budget_spec.py"):
    data=(ROOT/name).read_bytes()
    manifest["files"][name]={"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
manifest_path.write_bytes((json.dumps(manifest,indent=2,sort_keys=True)+"\n").encode("utf-8"))
print("SEC-123 patch applied")
