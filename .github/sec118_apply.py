#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
AXVEN = ROOT / "axven.py"
P2P = ROOT / "p2p.py"
SPEC = ROOT / "security_sec118_p2p_inbound_block_work_budget_spec.py"
MANIFEST = ROOT / "release_manifest.json"


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise AssertionError(f"{label}: expected exactly one anchor, got {count}")
    return text.replace(old, new, 1)


def write_lf(path, text):
    path.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))


ax = AXVEN.read_text(encoding="utf-8").replace("\r\n", "\n")
ax = replace_once(
    ax,
    '''    def add_block(self, block):\n        with self._state_lock:\n            return self._add_block_locked(block)\n\n    def _add_block_locked(self, block):\n''',
    '''    def add_block(self, block, work_gate=None):\n        with self._state_lock:\n            return self._add_block_locked(block, work_gate=work_gate)\n\n    def _add_block_locked(self, block, work_gate=None):\n''',
    "block work-gate signature",
)
ax = replace_once(
    ax,
    '''        err = _check_context(block, path, height)\n        if err:\n            return False, err\n        cw = parent_node.chainwork + work_of(block.target)\n''',
    '''        err = _check_context(block, path, height)\n        if err:\n            return False, err\n        # Optional local resource policy for untrusted ingress.  The gate is\n        # deliberately after duplicate/orphan/context checks but before any\n        # transaction/state-root/reorg validation work.  Normal consensus and\n        # local/outbound callers pass no gate and retain identical semantics.\n        if work_gate is not None and not work_gate():\n            return False, "validation work budget exceeded"\n        cw = parent_node.chainwork + work_of(block.target)\n''',
    "block work-gate placement",
)
ax = replace_once(
    ax,
    '''        self._connect_orphans(h)\n        return True, status\n''',
    '''        self._connect_orphans(h, work_gate=work_gate)\n        return True, status\n''',
    "orphan gate propagation",
)
ax = replace_once(
    ax,
    '''    def _connect_orphans(self, h):\n        queue = [h]\n        while queue:\n            parent = queue.pop()\n            for child in self.orphans.pop(parent, []):\n                child_hash = child.hash()\n                child_bytes = self.orphan_sizes.pop(child_hash, 0)\n                self.orphan_bytes = max(0, self.orphan_bytes - child_bytes)\n                ok, _ = self.add_block(child)\n                if ok:\n                    queue.append(child_hash)\n''',
    '''    def _connect_orphans(self, h, work_gate=None):\n        queue = [h]\n        while queue:\n            parent = queue.pop()\n            for child in self.orphans.pop(parent, []):\n                child_hash = child.hash()\n                child_bytes = self.orphan_sizes.pop(child_hash, 0)\n                self.orphan_bytes = max(0, self.orphan_bytes - child_bytes)\n                ok, _ = self.add_block(child, work_gate=work_gate)\n                if ok:\n                    queue.append(child_hash)\n''',
    "orphan child gate",
)
write_lf(AXVEN, ax)

p2p = P2P.read_text(encoding="utf-8").replace("\r\n", "\n")
p2p = replace_once(
    p2p,
    '''import json, socket, struct, threading, time\nfrom typing import Any, Dict, Optional\n''',
    '''import json, socket, struct, threading, time\nfrom collections import OrderedDict\nfrom typing import Any, Dict, Optional\n''',
    "OrderedDict import",
)
p2p = replace_once(
    p2p,
    '''MAX_INBOUND_PEERS = 32\nMAX_INBOUND_PEERS_PER_HOST = 4\nMAX_SYNC_BLOCKS = 128\n''',
    '''MAX_INBOUND_PEERS = 32\nMAX_INBOUND_PEERS_PER_HOST = 4\n# Public inbound block validation can otherwise drive full state-root work at\n# attacker-selected rates.  These are local ingress budgets, not consensus.\nINBOUND_BLOCK_WORK_GLOBAL_RATE = 2.0\nINBOUND_BLOCK_WORK_GLOBAL_BURST = 16\nINBOUND_BLOCK_WORK_PER_HOST_RATE = 1.0\nINBOUND_BLOCK_WORK_PER_HOST_BURST = 8\nMAX_INBOUND_BLOCK_WORK_HOSTS = 1024\nMAX_SYNC_BLOCKS = 128\n''',
    "block work constants",
)
limiter = '''\nclass _InboundBlockWorkLimiter:\n    """Thread-safe global + source-host token buckets for expensive blocks."""\n    def __init__(\n        self,\n        clock=time.monotonic,\n        global_rate=INBOUND_BLOCK_WORK_GLOBAL_RATE,\n        global_burst=INBOUND_BLOCK_WORK_GLOBAL_BURST,\n        per_host_rate=INBOUND_BLOCK_WORK_PER_HOST_RATE,\n        per_host_burst=INBOUND_BLOCK_WORK_PER_HOST_BURST,\n        max_hosts=MAX_INBOUND_BLOCK_WORK_HOSTS,\n    ):\n        self._clock=clock\n        self._global_rate=float(global_rate)\n        self._global_burst=float(global_burst)\n        self._per_host_rate=float(per_host_rate)\n        self._per_host_burst=float(per_host_burst)\n        self._max_hosts=int(max_hosts)\n        if (\n            self._global_rate <= 0\n            or self._global_burst < 1\n            or self._per_host_rate <= 0\n            or self._per_host_burst < 1\n            or self._max_hosts < 1\n        ):\n            raise ValueError("invalid inbound block work budget")\n        now=float(self._clock())\n        self._global_tokens=self._global_burst\n        self._global_last=now\n        self._hosts=OrderedDict()\n        self._lock=threading.Lock()\n\n    @staticmethod\n    def _refill(tokens, last, now, rate, burst):\n        elapsed=max(0.0, now-last)\n        return min(burst, tokens + elapsed*rate)\n\n    def consume(self, host):\n        if not isinstance(host,str) or not host:\n            return False\n        now=float(self._clock())\n        with self._lock:\n            global_tokens=self._refill(\n                self._global_tokens, self._global_last, now,\n                self._global_rate, self._global_burst,\n            )\n            entry=self._hosts.get(host)\n            if entry is None:\n                host_tokens=self._per_host_burst\n                host_last=now\n            else:\n                host_tokens, host_last=entry\n                host_tokens=self._refill(\n                    host_tokens, host_last, now,\n                    self._per_host_rate, self._per_host_burst,\n                )\n\n            allowed=(global_tokens >= 1.0 and host_tokens >= 1.0)\n            if allowed:\n                global_tokens-=1.0\n                host_tokens-=1.0\n\n            self._global_tokens=global_tokens\n            self._global_last=now\n            if entry is None and len(self._hosts) >= self._max_hosts:\n                self._hosts.popitem(last=False)\n            self._hosts[host]=(host_tokens,now)\n            self._hosts.move_to_end(host)\n            return allowed\n\n    def snapshot(self):\n        with self._lock:\n            return {\n                "global_tokens": self._global_tokens,\n                "hosts": len(self._hosts),\n            }\n\n'''
p2p = replace_once(
    p2p,
    '''class ProtocolError(ValueError): pass\n\ndef _reject_duplicate_json_keys(pairs):\n''',
    '''class ProtocolError(ValueError): pass\n''' + limiter + '''\ndef _reject_duplicate_json_keys(pairs):\n''',
    "limiter insertion",
)
p2p = replace_once(
    p2p,
    '''    def handle(self,msg):\n        typ=_validate_message_type(msg)\n''',
    '''    def handle(self,msg,block_work_gate=None):\n        typ=_validate_message_type(msg)\n''',
    "session gate signature",
)
p2p = replace_once(
    p2p,
    '''            block=axven.Block.from_dict(raw_block)\n            ok,status=self.chain.add_block(block)\n''',
    '''            block=axven.Block.from_dict(raw_block)\n            ok,status=self.chain.add_block(block,work_gate=block_work_gate)\n''',
    "single block gate",
)
p2p = replace_once(
    p2p,
    '''                b=axven.Block.from_dict(raw)\n                ok,status=self.chain.add_block(b)\n''',
    '''                b=axven.Block.from_dict(raw)\n                ok,status=self.chain.add_block(b,work_gate=block_work_gate)\n''',
    "batch block gate",
)
p2p = replace_once(
    p2p,
    '''def serve_connection(sock,session:PeerSession):\n''',
    '''def serve_connection(sock,session:PeerSession,block_work_gate=None):\n''',
    "serve gate signature",
)
p2p = replace_once(
    p2p,
    '''            reply=session.handle(msg)\n            if reply is not None: send_message(sock,reply)\n''',
    '''            reply=session.handle(msg,block_work_gate=block_work_gate)\n            if reply is not None: send_message(sock,reply)\n''',
    "serve gate forwarding",
)
p2p = replace_once(
    p2p,
    '''        self._sock=None; self._thread=None; self._stop=threading.Event()\n        self._clients=set(); self._client_hosts={}; self._lock=threading.Lock()\n''',
    '''        self._sock=None; self._thread=None; self._stop=threading.Event()\n        self._clients=set(); self._client_hosts={}; self._lock=threading.Lock()\n        self._block_work_limiter=_InboundBlockWorkLimiter()\n''',
    "server limiter init",
)
p2p = replace_once(
    p2p,
    '''                def worker(client=c):\n                    try: serve_connection(client,self.session)\n                    finally:\n''',
    '''                def worker(client=c,source_host=remote_host):\n                    gate=lambda: self._block_work_limiter.consume(source_host)\n                    try:\n                        serve_connection(\n                            client,self.session,block_work_gate=gate\n                        )\n                    finally:\n''',
    "server host gate",
)
write_lf(P2P, p2p)

spec = r'''#!/usr/bin/env python3
"""SEC-118 bound public inbound expensive block-validation work."""

import copy
import inspect

import axven
import p2p


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = float(now)
    def __call__(self):
        return self.now
    def advance(self, seconds):
        self.now += float(seconds)


def remine(block):
    block.nonce = 0
    while not block.pow_ok():
        block.nonce += 1
    return block


def main():
    checks = []
    def green(name, cond):
        assert cond, name
        checks.append(name)
        print("[GREEN]", name)

    green(
        "inbound block work budgets pinned",
        p2p.INBOUND_BLOCK_WORK_GLOBAL_RATE == 2.0
        and p2p.INBOUND_BLOCK_WORK_GLOBAL_BURST == 16
        and p2p.INBOUND_BLOCK_WORK_PER_HOST_RATE == 1.0
        and p2p.INBOUND_BLOCK_WORK_PER_HOST_BURST == 8
        and p2p.MAX_INBOUND_BLOCK_WORK_HOSTS == 1024,
    )

    clock = FakeClock()
    limiter = p2p._InboundBlockWorkLimiter(clock=clock)
    results = [limiter.consume("198.51.100.1") for _ in range(9)]
    green(
        "single source burst is bounded across repeated work",
        results[:8] == [True] * 8 and results[8] is False,
    )
    clock.advance(1.0)
    green(
        "single source budget refills at pinned rate",
        limiter.consume("198.51.100.1") is True
        and limiter.consume("198.51.100.1") is False,
    )

    global_limiter = p2p._InboundBlockWorkLimiter(clock=FakeClock())
    allowed = [
        global_limiter.consume(f"203.0.113.{i}")
        for i in range(1, 18)
    ]
    green(
        "distributed sources remain globally bounded",
        allowed[:16] == [True] * 16 and allowed[16] is False,
    )

    tiny = p2p._InboundBlockWorkLimiter(clock=FakeClock(), max_hosts=3)
    for i in range(12):
        tiny.consume(f"192.0.2.{i}")
    green(
        "source bucket memory is independently bounded",
        tiny.snapshot()["hosts"] <= 3,
    )

    wallet = axven.Wallet()
    source = axven.Blockchain()
    candidate = source.build_candidate(wallet.address)
    target = axven.Blockchain()
    before_index = set(target.index)
    before_utxo = copy.deepcopy(target.utxo)
    called = []
    ok, reason = target.add_block(
        candidate,
        work_gate=lambda: called.append("gate") or False,
    )
    green(
        "context-valid block is stopped before expensive state validation",
        (not ok)
        and reason == "validation work budget exceeded"
        and called == ["gate"]
        and set(target.index) == before_index
        and target.utxo == before_utxo,
    )

    gate_calls = []
    orphan = copy.deepcopy(candidate)
    orphan.previous_hash = "ab" * 32
    remine(orphan)
    ok, status = target.add_block(
        orphan,
        work_gate=lambda: gate_calls.append("unexpected") or False,
    )
    green(
        "unknown-parent orphan admission consumes no validation token",
        (not ok) and status == "orphan" and gate_calls == [],
    )

    target2 = axven.Blockchain()
    ok, status = target2.add_block(candidate)
    assert ok and status == "extended"
    duplicate_gate = []
    ok, status = target2.add_block(
        candidate,
        work_gate=lambda: duplicate_gate.append("unexpected") or False,
    )
    green(
        "duplicate rejection consumes no validation token",
        (not ok) and status == "duplicate" and duplicate_gate == [],
    )

    source2 = axven.Blockchain()
    parent = source2.mine(wallet.address)
    child = source2.mine(wallet.address)
    target3 = axven.Blockchain()
    orphan_gate_calls = []
    ok, status = target3.add_block(
        child,
        work_gate=lambda: orphan_gate_calls.append("unexpected") or False,
    )
    assert not ok and status == "orphan" and orphan_gate_calls == []
    budget = iter([True, False])
    ok, status = target3.add_block(parent, work_gate=lambda: next(budget))
    green(
        "connected orphan cannot bypass the parent validation budget",
        ok
        and status == "extended"
        and target3.tip.hash() == parent.hash()
        and child.hash() not in target3.index,
    )
    ok, status = target3.add_block(child, work_gate=lambda: True)
    assert ok and status == "extended"

    source4 = axven.Blockchain()
    block4 = source4.build_candidate(wallet.address)
    session = p2p.PeerSession(axven.Blockchain(), None)
    msg = {"type": "block", "block": block4.to_dict()}
    exhausted = p2p._InboundBlockWorkLimiter(
        clock=FakeClock(), global_burst=1, per_host_burst=1
    )
    assert exhausted.consume("198.51.100.77") is True
    try:
        session.handle(
            msg,
            block_work_gate=lambda: exhausted.consume("198.51.100.77"),
        )
        raised = False
    except p2p.ProtocolError as exc:
        raised = "validation work budget exceeded" in str(exc)
    green("PeerSession enforces inbound block work gate", raised)

    outbound_session = p2p.PeerSession(axven.Blockchain(), None)
    reply = outbound_session.handle(msg)
    green(
        "internal/outbound block handling remains unthrottled",
        reply["type"] == "accepted"
        and reply["status"] == "extended"
        and outbound_session.chain.validate(),
    )

    add_src = inspect.getsource(axven.Blockchain._add_block_locked)
    orphan_src = inspect.getsource(axven.Blockchain._connect_orphans)
    serve_src = inspect.getsource(p2p.serve_connection)
    server_src = inspect.getsource(p2p.NodeServer.start)
    sync_src = inspect.getsource(p2p.sync_once)
    green(
        "production wiring meters only expensive inbound block validation",
        '_check_context(block, path, height)' in add_src
        and 'work_gate is not None and not work_gate()' in add_src
        and add_src.index('_check_context(block, path, height)')
            < add_src.index('work_gate is not None and not work_gate()')
        and 'work_gate=work_gate' in orphan_src
        and 'block_work_gate=block_work_gate' in serve_src
        and '_block_work_limiter.consume(source_host)' in server_src
        and 'block_work_gate' not in sync_src,
    )

    print(f"SEC-118 inbound block work budget: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
'''
write_lf(SPEC, spec)

manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
for rel in ("axven.py", "p2p.py", SPEC.name):
    path = ROOT / rel
    data = path.read_bytes().replace(b"\r\n", b"\n")
    path.write_bytes(data)
    manifest["files"][rel] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest["consensus_code_sha256"] = hashlib.sha256(AXVEN.read_bytes()).hexdigest()
MANIFEST.write_bytes((json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
print("SEC-118 patch staged with LF-normalized manifest hashes")
