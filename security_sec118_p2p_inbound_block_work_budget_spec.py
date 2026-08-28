#!/usr/bin/env python3
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

    class LegacyCompatibleChain:
        def __init__(self):
            self.seen = []
        def add_block(self, block):
            self.seen.append(block)
            return True, "extended"

    legacy_single = LegacyCompatibleChain()
    legacy_reply = p2p.PeerSession(legacy_single, None).handle(msg)
    green(
        "unmetered single-block session preserves legacy add_block call shape",
        legacy_reply["type"] == "accepted"
        and legacy_reply["status"] == "extended"
        and len(legacy_single.seen) == 1,
    )

    legacy_batch = LegacyCompatibleChain()
    legacy_batch_reply = p2p.PeerSession(legacy_batch, None).handle(
        {"type": "blocks", "blocks": [block4.to_dict()]}
    )
    green(
        "unmetered block-batch session preserves legacy add_block call shape",
        legacy_batch_reply == {"type": "accepted", "kind": "blocks", "count": 1}
        and len(legacy_batch.seen) == 1,
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
