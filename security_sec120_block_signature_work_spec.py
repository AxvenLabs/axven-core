#!/usr/bin/env python3
"""SEC-120 bound block-contained signature verification and fork replay work."""

import copy
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


def mine_chain(count, wallet):
    chain = axven.Blockchain()
    for _ in range(count):
        chain.mine(wallet.address)
    return chain


def replay_prefix(source, height):
    out = axven.Blockchain()
    for block in source.blocks[1:height + 1]:
        ok, status = out.add_block(block)
        assert ok and status == "extended"
    return out


def add_signed_spend(chain, wallet, recipient=None):
    recipient = recipient or axven.Wallet().address
    txid, index, amount = chain.spendable(wallet.address)[0]
    tx = axven.Transaction(
        [axven.TxInput(txid, index)],
        [axven.TxOutput(amount - 1, recipient)],
    )
    tx.inputs[0] = wallet.sign_input(tx, 0)
    mp = axven.Mempool(chain)
    mp.add(tx)
    return tx, chain.build_candidate(wallet.address, mp)


def main():
    checks = []
    def green(name, cond):
        assert cond, name
        checks.append(name)
        print("[GREEN]", name)

    green(
        "block signature work budgets and cache bound are pinned safely",
        axven.MAX_VERIFIED_INPUT_CACHE == 32768
        and p2p.MIN_VALID_ED25519_AUTH_TEXT_BYTES == 132
        and p2p.MAX_VALID_BLOCK_SIGNATURE_WORK
            > int(axven.CHAIN_CONFIG["max_block_bytes"]) // 132
        and p2p.INBOUND_BLOCK_SIGNATURE_WORK_PER_HOST_BURST
            == p2p.MAX_VALID_BLOCK_SIGNATURE_WORK
        and p2p.INBOUND_BLOCK_SIGNATURE_WORK_GLOBAL_BURST
            >= 4 * p2p.INBOUND_BLOCK_SIGNATURE_WORK_PER_HOST_BURST,
    )

    clock = FakeClock()
    limiter = p2p._InboundBlockSignatureWorkLimiter(
        clock=clock, global_rate=10, global_burst=20,
        per_host_rate=5, per_host_burst=10, max_hosts=2,
    )
    green(
        "single source weighted block signature burst is bounded",
        limiter.consume("192.0.2.1", 6)
        and not limiter.consume("192.0.2.1", 5),
    )
    clock.advance(1.0)
    green(
        "block signature work budget refills at configured rate",
        limiter.consume("192.0.2.1", 5),
    )
    distributed = p2p._InboundBlockSignatureWorkLimiter(
        clock=FakeClock(), global_rate=1, global_burst=8,
        per_host_rate=1, per_host_burst=8, max_hosts=4,
    )
    green(
        "distributed block signature sources remain globally bounded",
        distributed.consume("192.0.2.10", 4)
        and distributed.consume("192.0.2.11", 4)
        and not distributed.consume("192.0.2.12", 1),
    )
    mem = p2p._InboundBlockSignatureWorkLimiter(
        clock=FakeClock(), global_rate=100, global_burst=100,
        per_host_rate=100, per_host_burst=100, max_hosts=2,
    )
    mem.consume("198.51.100.1", 1)
    mem.consume("198.51.100.2", 1)
    mem.consume("198.51.100.3", 1)
    green("block signature limiter source memory is bounded", mem.snapshot()["hosts"] == 2)

    cache = axven._VerifiedInputCache(max_entries=2)
    cache.remember("a"); cache.remember("b")
    assert cache.contains("a")
    cache.remember("c")
    green(
        "positive verification cache is bounded LRU",
        len(cache) == 2 and cache.contains("a") and cache.contains("c")
        and not cache.contains("b"),
    )

    miner = axven.Wallet()
    source = mine_chain(axven.COINBASE_MATURITY + 1, miner)
    tx, block = add_signed_spend(source, miner)
    base_utxo = copy.deepcopy(source.utxo)
    base_issued = source.total_issued
    height = source.tip.height + 1
    shared_cache = axven._VerifiedInputCache()
    verify_calls = []
    gate_calls = []
    original_verify = axven.verify_input
    def counted_verify(*args, **kwargs):
        verify_calls.append(1)
        return original_verify(*args, **kwargs)
    axven.verify_input = counted_verify
    try:
        first_utxo = copy.deepcopy(base_utxo)
        ok, reason, _undo, _reward, _fees = axven._apply_forward(
            block, first_utxo, height, base_issued,
            signature_work_gate=lambda cost: gate_calls.append(cost) or True,
            verification_cache=shared_cache,
        )
        first_calls = len(verify_calls)
        second_gate = []
        second_utxo = copy.deepcopy(base_utxo)
        ok2, reason2, _undo2, _reward2, _fees2 = axven._apply_forward(
            block, second_utxo, height, base_issued,
            signature_work_gate=lambda cost: second_gate.append(cost) or True,
            verification_cache=shared_cache,
        )
    finally:
        axven.verify_input = original_verify
    green(
        "fresh valid block charges exact Ed25519 work before one verify",
        ok and reason == "OK" and gate_calls == [1] and first_calls == 1,
    )
    green(
        "exact positive cache hit skips repeated crypto and preserves state",
        ok2 and reason2 == "OK" and len(verify_calls) == first_calls
        and second_gate == [] and second_utxo == first_utxo,
    )

    blocked_utxo = copy.deepcopy(base_utxo)
    before_blocked = copy.deepcopy(blocked_utxo)
    called = []
    def forbidden_verify(*_args, **_kwargs):
        called.append(1)
        raise AssertionError("verify_input ran after exhausted work gate")
    axven.verify_input = forbidden_verify
    try:
        ok, reason, *_ = axven._apply_forward(
            block, blocked_utxo, height, base_issued,
            signature_work_gate=lambda _cost: False,
            verification_cache=axven._VerifiedInputCache(),
        )
    finally:
        axven.verify_input = original_verify
    green(
        "exhausted block signature budget stops before crypto and rolls back",
        (not ok) and "Signature work budget exceeded" in reason
        and called == [] and blocked_utxo == before_blocked,
    )

    bad_output = copy.deepcopy(block)
    bad_output.transactions[1]["outputs"][0]["amount"] = 0
    cheap_gate = []
    called = []
    axven.verify_input = forbidden_verify
    try:
        bad_utxo = copy.deepcopy(base_utxo)
        ok, reason, *_ = axven._transition(
            bad_output, bad_utxo, height, base_issued,
            signature_work_gate=lambda cost: cheap_gate.append(cost) or True,
            verification_cache=axven._VerifiedInputCache(),
        )
    finally:
        axven.verify_input = original_verify
    green(
        "cheap invalid block output consumes no signature work",
        (not ok) and "Dust output" in reason and cheap_gate == [] and called == [],
    )

    bad_sig = copy.deepcopy(block)
    bad_sig.transactions[1]["inputs"][0]["signature"] = "AAAA"
    failed_cache = axven._VerifiedInputCache()
    failed_gate = []
    bad_utxo = copy.deepcopy(base_utxo)
    ok, reason, *_ = axven._transition(
        bad_sig, bad_utxo, height, base_issued,
        signature_work_gate=lambda cost: failed_gate.append(cost) or True,
        verification_cache=failed_cache,
    )
    green(
        "failed signature is charged but never cached",
        (not ok) and "Bad signature" in reason and failed_gate == [1]
        and len(failed_cache) == 0,
    )

    target = replay_prefix(source, source.tip.height)
    verify_calls = []
    axven.verify_input = counted_verify
    try:
        ok, reason = target.add_block(
            block, signature_work_gate=lambda _cost: False
        )
    finally:
        axven.verify_input = original_verify
    green(
        "Blockchain enforces signature work gate before verification",
        (not ok) and "Signature work budget exceeded" in reason and verify_calls == [],
    )

    target2 = replay_prefix(source, source.tip.height)
    session = p2p.PeerSession(target2, None)
    try:
        session.handle(
            {"type": "block", "block": block.to_dict()},
            block_work_gate=lambda: True,
            block_signature_work_gate=lambda _cost: False,
        )
        peer_blocked = False
    except p2p.ProtocolError as exc:
        peer_blocked = "Signature work budget exceeded" in str(exc)
    green("PeerSession enforces public block signature gate", peer_blocked)

    # Exercise the real fork-replay amplifier: the side block contains one
    # signed spend, then a child makes the branch heavier.  The already
    # positively verified side signature must not run again during reorg replay.
    active = mine_chain(axven.COINBASE_MATURITY + 2, miner)
    fork_parent_height = active.tip.height - 1
    side_builder = replay_prefix(active, fork_parent_height)
    _side_tx, side_block = add_signed_spend(side_builder, miner)
    ok, status = active.add_block(
        side_block, signature_work_gate=lambda _cost: True
    )
    assert ok and status == "side-chain"
    ok, status = side_builder.add_block(side_block)
    assert ok and status == "extended"
    child = side_builder.build_candidate(miner.address)
    replay_verify_calls = []
    def replay_counted(*args, **kwargs):
        replay_verify_calls.append(1)
        return original_verify(*args, **kwargs)
    axven.verify_input = replay_counted
    try:
        ok, status = active.add_block(
            child, signature_work_gate=lambda _cost: True
        )
    finally:
        axven.verify_input = original_verify
    green(
        "heavier fork replay reuses exact positive signatures without reverify",
        ok and status == "reorg" and replay_verify_calls == [] and active.validate(),
    )

    class LegacyCompatibleChain:
        def __init__(self): self.seen = []
        def add_block(self, candidate):
            self.seen.append(candidate)
            return True, "extended"
    legacy = LegacyCompatibleChain()
    reply = p2p.PeerSession(legacy, None).handle(
        {"type": "block", "block": block.to_dict()}
    )
    green(
        "unmetered block session preserves legacy add_block call shape",
        reply["type"] == "accepted" and reply["status"] == "extended"
        and len(legacy.seen) == 1,
    )

    trans_src = inspect.getsource(axven._transition)
    state_src = inspect.getsource(axven.Blockchain._state_for_index_node)
    reorg_src = inspect.getsource(axven.Blockchain._reorg_to)
    orphan_src = inspect.getsource(axven.Blockchain._connect_orphans)
    serve_src = inspect.getsource(p2p.serve_connection)
    server_src = inspect.getsource(p2p.NodeServer.start)
    validate_src = inspect.getsource(axven.Blockchain.validate_reason)
    green(
        "production wiring meters uncached block crypto while full validation stays independent",
        "signature_work_gate(crypto_work)" in trans_src
        and trans_src.index("signature_work_gate(crypto_work)") < trans_src.index("verify_input(i, u, sh, height)")
        and "verification_cache=self._verified_input_cache" in state_src
        and "verification_cache=self._verified_input_cache" in reorg_src
        and "signature_work_gate=signature_work_gate" in orphan_src
        and "block_signature_work_gate=block_signature_work_gate" in serve_src
        and "_block_signature_work_limiter.consume(source_host,cost)" in server_src
        and "verification_cache" not in validate_src
        and "signature_work_gate" not in validate_src,
    )

    print(f"SEC-120 block signature work: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
