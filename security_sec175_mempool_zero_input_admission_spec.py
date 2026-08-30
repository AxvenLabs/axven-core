#!/usr/bin/env python3
"""SEC-175: zero-input non-coinbase transactions must not enter the mempool."""
from __future__ import annotations

import inspect

import axven
import p2p


def main():
    checks=[]
    def ok(name, value):
        assert value, name
        checks.append(name)
        print(f"[GREEN] {name}")

    # Optional coinbase_height metadata makes otherwise empty transactions
    # distinct, so without an input-domain gate they can cheaply fill the
    # bounded mempool while consuming zero signature-work units.
    junk=[axven.Transaction([], [], coinbase_height=h) for h in range(8)]
    ok("zero-input metadata variants have distinct txids", len({tx.txid() for tx in junk}) == len(junk))

    chain=axven.Blockchain(); mp=axven.Mempool(chain)
    gate_calls=[]
    rejected=0
    for tx in junk:
        try:
            mp.add(tx, work_gate=lambda cost: gate_calls.append(cost) or True)
        except ValueError as exc:
            assert "at least one input" in str(exc)
            rejected += 1
    ok("all zero-input variants rejected", rejected == len(junk))
    ok("zero-input rejection leaves mempool empty", not mp.txs and mp.total_bytes == 0)
    ok("zero-input junk consumes no crypto budget", gate_calls == [])

    # Public P2P still accepts the canonical wire envelope but the real
    # mempool policy fails closed instead of publishing an accepted ack.
    p2p_chain=axven.Blockchain(); p2p_mp=axven.Mempool(p2p_chain)
    msg={"type":"tx","tx":junk[0].to_dict()}
    try:
        p2p.PeerSession(p2p_chain,p2p_mp).handle(msg,tx_work_gate=lambda cost: True)
    except ValueError as exc:
        p2p_rejected="at least one input" in str(exc)
    else:
        p2p_rejected=False
    ok("public relay cannot admit zero-input tx", p2p_rejected and not p2p_mp.txs)

    # Healthy spend admission remains unchanged.
    healthy_chain=axven.Blockchain(); healthy_mp=axven.Mempool(healthy_chain); w=axven.Wallet()
    prev="75"*32
    healthy_chain.utxo[axven.outpoint(prev,0)]={
        "amount":100_000,
        "recipient":w.address,
        "coinbase":False,
        "height":0,
    }
    unsigned=axven.Transaction(
        [axven.TxInput(prev,0)],
        [axven.TxOutput(90_000,w.address)],
    )
    signed=axven.Transaction([w.sign_input(unsigned,0)],unsigned.outputs)
    healthy_cost=[]
    tid=healthy_mp.add(signed,work_gate=lambda cost: healthy_cost.append(cost) or True)
    ok("healthy signed spend remains accepted", tid in healthy_mp.txs and healthy_cost == [1])

    src=inspect.getsource(axven.Mempool._add_locked)
    empty_guard=src.index("if not inputs:")
    ok("zero-input guard precedes txid work", empty_guard < src.index("tid = tx.txid()"))
    ok("zero-input guard precedes byte accounting", empty_guard < src.index("serialized_transaction_size(tx)"))
    ok("zero-input guard precedes crypto gate", empty_guard < src.index("work_gate(auth_work_units)"))

    ok("chain id unchanged", axven.CHAIN_ID == "axven-devnet-2")
    ok("config fingerprint unchanged", axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
    ok("genesis unchanged", axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3")

    print(f"SEC-175 mempool zero-input admission: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
