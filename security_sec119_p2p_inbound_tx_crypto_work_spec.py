#!/usr/bin/env python3
"""SEC-119 bounds public standalone transaction signature-validation work."""
import inspect

import axven
import p2p


class FakeClock:
    def __init__(self): self.now = 0.0
    def __call__(self): return self.now
    def advance(self, seconds): self.now += seconds


def green(name, condition):
    assert condition, name
    print(f"[GREEN] {name}")


def synthetic_input(prev, scheme):
    if scheme == axven.SCHEME_ED25519:
        return axven.TxInput(prev, 0, signature="sig", public_key="pub")
    if scheme == axven.SCHEME_ML_DSA:
        return axven.TxInput(
            prev, 0, scheme=scheme, signature="sig", public_key="pub"
        )
    return axven.TxInput(
        prev, 0, scheme=scheme,
        ed_signature="es", ed_public_key="ep",
        ml_signature="ms", ml_public_key="mp",
    )


def inject_utxo(chain, prev, recipient, amount=100_000):
    chain.utxo[axven.outpoint(prev, 0)] = {
        "amount": amount,
        "recipient": recipient,
        "coinbase": False,
        "height": 0,
    }


def main():
    checks = []
    def ok(name, condition):
        green(name, condition); checks.append(name)

    max_cost = p2p.MAX_P2P_TX_INPUTS * p2p.INBOUND_TX_WORK_HYBRID
    ok(
        "weighted inbound TX budgets pinned and maximum relay fits burst",
        p2p.INBOUND_TX_WORK_ED25519 == 1
        and p2p.INBOUND_TX_WORK_ML_DSA == 4
        and p2p.INBOUND_TX_WORK_HYBRID == 5
        and p2p.INBOUND_TX_WORK_PER_HOST_BURST >= max_cost
        and p2p.INBOUND_TX_WORK_GLOBAL_BURST >= max_cost
        and p2p.MAX_INBOUND_TX_WORK_HOSTS == 1024,
    )

    clock = FakeClock()
    limiter = p2p._InboundTxWorkLimiter(
        clock=clock, global_rate=10, global_burst=10,
        per_host_rate=5, per_host_burst=10, max_hosts=3,
    )
    ok("single source weighted burst is bounded", limiter.consume("a", 6) and not limiter.consume("a", 5))
    clock.advance(1.0)
    ok("single source weighted budget refills", limiter.consume("a", 5))

    clock2 = FakeClock()
    distributed = p2p._InboundTxWorkLimiter(
        clock=clock2, global_rate=1, global_burst=6,
        per_host_rate=10, per_host_burst=6, max_hosts=8,
    )
    ok(
        "distributed sources remain globally bounded",
        distributed.consume("a", 3)
        and distributed.consume("b", 3)
        and not distributed.consume("c", 1),
    )
    for host in ("d", "e", "f", "g"):
        distributed.consume(host, 1)
    ok("TX limiter source memory is independently bounded", distributed.snapshot()["hosts"] <= 8)

    # Cheap missing-input rejection must not consume the gate.
    chain = axven.Blockchain(); mp = axven.Mempool(chain)
    missing = axven.Transaction(
        [axven.TxInput("11" * 32, 0, signature="sig", public_key="pub")],
        [axven.TxOutput(1, "N" + "1" * 40)],
    )
    gate_calls = []
    try: mp.add(missing, work_gate=lambda cost: gate_calls.append(cost) or True)
    except ValueError as exc: missing_rejected = "Input not found" in str(exc)
    else: missing_rejected = False
    ok("missing-input junk consumes no crypto budget", missing_rejected and gate_calls == [])

    # Cheap output failure likewise stays ahead of the gate.
    chain2 = axven.Blockchain(); mp2 = axven.Mempool(chain2)
    prev2 = "22" * 32
    inject_utxo(chain2, prev2, "N" + "2" * 40)
    dust = axven.Transaction(
        [synthetic_input(prev2, axven.SCHEME_ED25519)],
        [axven.TxOutput(0, "N" + "3" * 40)],
    )
    dust_calls = []
    try: mp2.add(dust, work_gate=lambda cost: dust_calls.append(cost) or True)
    except ValueError as exc: dust_rejected = "Dust" in str(exc)
    else: dust_rejected = False
    ok("cheap output failure consumes no crypto budget", dust_rejected and dust_calls == [])

    # Cost is derived from resolved UTXO schemes, not attacker-selected size.
    chain3 = axven.Blockchain(); mp3 = axven.Mempool(chain3)
    prevs = ["31" * 32, "32" * 32, "33" * 32]
    recipients = ["N" + "a" * 40, "M" + "b" * 40, "H" + "c" * 40]
    schemes = [axven.SCHEME_ED25519, axven.SCHEME_ML_DSA, axven.SCHEME_HYBRID]
    for prev, recipient in zip(prevs, recipients): inject_utxo(chain3, prev, recipient)
    weighted = axven.Transaction(
        [synthetic_input(prev, scheme) for prev, scheme in zip(prevs, schemes)],
        [axven.TxOutput(1, "N" + "d" * 40)],
    )
    captured = []
    original_verify = axven.verify_input
    axven.verify_input = lambda *args, **kwargs: True
    try:
        mp3.add(weighted, work_gate=lambda cost: captured.append(cost) or True)
    finally:
        axven.verify_input = original_verify
    ok("resolved Ed25519 ML-DSA and hybrid inputs are weighted exactly", captured == [10])

    # Exhaustion occurs before the first cryptographic verification.
    chain4 = axven.Blockchain(); mp4 = axven.Mempool(chain4)
    prev4 = "44" * 32
    inject_utxo(chain4, prev4, "N" + "4" * 40)
    candidate = axven.Transaction(
        [synthetic_input(prev4, axven.SCHEME_ED25519)],
        [axven.TxOutput(90_000, "N" + "5" * 40)],
    )
    verify_calls = []
    axven.verify_input = lambda *args, **kwargs: verify_calls.append(1) or True
    try:
        try: mp4.add(candidate, work_gate=lambda cost: False)
        except ValueError as exc: budget_rejected = "work budget exceeded" in str(exc)
        else: budget_rejected = False
    finally:
        axven.verify_input = original_verify
    ok("exhausted TX budget stops before signature verification", budget_rejected and verify_calls == [])

    # Healthy admission remains identical when budget is available.
    chain5 = axven.Blockchain(); mp5 = axven.Mempool(chain5); wallet = axven.Wallet()
    prev5 = "55" * 32
    inject_utxo(chain5, prev5, wallet.address)
    unsigned = axven.Transaction(
        [axven.TxInput(prev5, 0)],
        [axven.TxOutput(90_000, wallet.address)],
    )
    signed = axven.Transaction([wallet.sign_input(unsigned, 0)], unsigned.outputs)
    healthy_cost = []
    tid = mp5.add(signed, work_gate=lambda cost: healthy_cost.append(cost) or True)
    ok("valid transaction is admitted when crypto budget is available", tid in mp5.txs and healthy_cost == [1])

    # P2P uses the gate, while the legacy/unmetered mempool API stays compatible.
    chain6 = axven.Blockchain(); mp6 = axven.Mempool(chain6); wallet6 = axven.Wallet()
    prev6 = "66" * 32
    inject_utxo(chain6, prev6, wallet6.address)
    u6 = axven.Transaction([axven.TxInput(prev6, 0)], [axven.TxOutput(90_000, wallet6.address)])
    s6 = axven.Transaction([wallet6.sign_input(u6, 0)], u6.outputs)
    msg = {"type": "tx", "tx": s6.to_dict()}
    try:
        p2p.PeerSession(chain6, mp6).handle(msg, tx_work_gate=lambda cost: False)
    except ValueError as exc:
        peer_rejected = "work budget exceeded" in str(exc)
    else:
        peer_rejected = False
    ok("PeerSession enforces inbound TX crypto-work gate", peer_rejected and not mp6.txs)

    class LegacyMempool:
        def __init__(self): self.seen = []
        def add(self, tx): self.seen.append(tx); return tx.txid()
    legacy = LegacyMempool()
    reply = p2p.PeerSession(object(), legacy).handle(msg)
    ok(
        "unmetered session preserves legacy mempool add call shape",
        reply["type"] == "accepted" and len(legacy.seen) == 1,
    )

    # Direct/local mempool admission remains unthrottled by default.
    chain7 = axven.Blockchain(); mp7 = axven.Mempool(chain7); wallet7 = axven.Wallet()
    prev7 = "77" * 32
    inject_utxo(chain7, prev7, wallet7.address)
    u7 = axven.Transaction([axven.TxInput(prev7, 0)], [axven.TxOutput(90_000, wallet7.address)])
    s7 = axven.Transaction([wallet7.sign_input(u7, 0)], u7.outputs)
    mp7.add(s7)
    ok("local direct mempool admission remains unthrottled", s7.txid() in mp7.txs)

    mempool_src = inspect.getsource(axven.Mempool._add_locked)
    session_src = inspect.getsource(p2p.PeerSession.handle)
    serve_src = inspect.getsource(p2p.serve_connection)
    server_src = inspect.getsource(p2p.NodeServer.start)
    sync_src = inspect.getsource(p2p.sync_once)
    ok(
        "production wiring meters only expensive public standalone TX validation",
        'work_gate is not None and not work_gate(auth_work_units)' in mempool_src
        and mempool_src.index('Input not found / unconfirmed') < mempool_src.index('work_gate is not None and not work_gate(auth_work_units)')
        and mempool_src.index('Dust / non-positive output') < mempool_src.index('work_gate is not None and not work_gate(auth_work_units)')
        and mempool_src.index('work_gate is not None and not work_gate(auth_work_units)') < mempool_src.index('verify_input(i, u, sh, next_height)')
        and 'tx_work_gate=tx_work_gate' in serve_src
        and '_tx_work_limiter.consume' in server_src
        and 'work_gate=tx_work_gate' in session_src
        and 'tx_work_gate' not in sync_src,
    )

    print(f"SEC-119 inbound TX crypto-work budget: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
