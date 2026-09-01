#!/usr/bin/env python3
"""RUST-005: real-transition replay/reorg shadow equivalence for native SMT."""
from __future__ import annotations

from pathlib import Path

import axven
import axven_native

ROOT = Path(__file__).resolve().parent
HEX = frozenset("0123456789abcdef")
ACTIVATION = 10_000
shadow_states = 0


def _clone_block(block):
    return axven.Block.from_dict(block.to_dict())


def _rows(utxo):
    return [
        (op, u["amount"], u["recipient"], u["coinbase"], u["height"])
        for op, u in utxo.items()
    ]


def _root_shape(root):
    assert type(root) is str
    assert len(root) == 64
    assert all(ch in HEX for ch in root)
    return root


def _shadow(chain, label):
    global shadow_states
    python_root = _root_shape(axven.smt_root_reference(chain.utxo))
    native_root = _root_shape(axven_native.smt_root_mirror(_rows(chain.utxo)))
    activation_root = _root_shape(axven.expected_state_root(chain.utxo, ACTIVATION))
    assert native_root == python_root, (label, native_root, python_root)
    assert activation_root == python_root, (label, activation_root, python_root)

    # The live rehearsal intentionally remains pre-activation, so its real
    # header commitment must continue to use the existing legacy scheme.
    assert chain.tip.height < ACTIVATION
    assert axven.state_root_scheme(chain.tip.height) == "legacy"
    live_root = _root_shape(axven.expected_state_root(chain.utxo, chain.tip.height))
    assert chain.tip.utxo_state_root == live_root, (label, chain.tip.height)
    shadow_states += 1
    return python_root


def _assert_production_python_only():
    for name in ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py"):
        assert "axven_native" not in (ROOT / name).read_text(encoding="utf-8"), name


def main() -> None:
    _assert_production_python_only()
    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    assert axven.CHAIN_CONFIG["smt_activation_height"] == ACTIVATION
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2_000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5_000
    assert axven.state_root_scheme(ACTIVATION - 1) == "legacy"
    assert axven.state_root_scheme(ACTIVATION) == "sparse"
    print("[GREEN] canonical identity and activation boundary unchanged")

    chain = axven.Blockchain()
    miner = axven.Wallet()
    receiver = axven.Wallet()
    _shadow(chain, "genesis")

    # Real production mining transitions; shadow every accepted state.
    maturity_height = axven.COINBASE_MATURITY + 2
    for height in range(1, maturity_height + 1):
        block = chain.mine(miner.address)
        assert block.height == height
        _shadow(chain, f"mine-{height}")
    assert chain.tip.height == maturity_height
    assert chain.validate_reason() == (True, "OK")
    print(f"[GREEN] {maturity_height} production mining transitions shadow-equivalent")

    # Mature spend through the real Mempool -> miner -> add_block path.
    spendable = chain.spendable(miner.address)
    assert spendable
    txid, index, amount = spendable[0]
    fee = 1
    tx = axven.Transaction(
        [axven.TxInput(txid, index)],
        [axven.TxOutput(amount - fee, receiver.address)],
    )
    tx.inputs = [miner.sign_input(tx, 0)]
    mempool = axven.Mempool(chain)
    accepted_txid = mempool.add(tx)
    assert accepted_txid == tx.txid()
    spend_block = chain.mine(miner.address, mempool)
    assert spend_block.height == maturity_height + 1
    assert chain.balance(receiver.address) == amount - fee
    _shadow(chain, "mature-signed-spend")
    assert chain.validate_reason() == (True, "OK")
    print("[GREEN] mature signed spend and fee-bearing block shadow-equivalent")

    # Clone the exact active state through public add_block replay, then create
    # a competing branch from this fork point. Active gets 2 blocks, fork gets
    # 4; feeding the fork back must pass side-state validation and then reorg.
    fork_point = chain.tip.height
    fork = axven.Blockchain()
    for block in chain.blocks[1:]:
        ok, status = fork.add_block(_clone_block(block))
        assert ok and status == "extended", (block.height, status)
    assert fork.utxo == chain.utxo
    assert fork.tip.hash() == chain.tip.hash()
    _shadow(fork, "fork-clone")

    for i in range(2):
        chain.mine(miner.address)
        _shadow(chain, f"active-branch-{i + 1}")

    fork_miner = axven.Wallet()
    for i in range(4):
        fork.mine(fork_miner.address)
        _shadow(fork, f"fork-branch-{i + 1}")

    statuses = []
    for block in fork.blocks[fork_point + 1:]:
        ok, status = chain.add_block(_clone_block(block))
        assert ok, (block.height, status)
        statuses.append(status)
        _shadow(chain, f"ingress-{block.height}-{status}")

    assert statuses[:2] == ["side-chain", "side-chain"], statuses
    assert "reorg" in statuses, statuses
    assert chain.tip.hash() == fork.tip.hash()
    assert chain.utxo == fork.utxo
    assert chain.validate_reason() == (True, "OK")
    assert fork.validate_reason() == (True, "OK")
    print("[GREEN] side-chain admission and heavier-chain reorg shadow-equivalent")

    # Fresh active-chain replay from genesis. This independently exercises the
    # production add_block/_apply_forward path for every final canonical block.
    replay = axven.Blockchain()
    _shadow(replay, "replay-genesis")
    for block in chain.blocks[1:]:
        ok, status = replay.add_block(_clone_block(block))
        assert ok and status == "extended", (block.height, status)
        _shadow(replay, f"replay-{block.height}")
    assert replay.tip.hash() == chain.tip.hash()
    assert replay.utxo == chain.utxo
    assert replay.total_issued == chain.total_issued
    assert replay.chainwork == chain.chainwork
    assert replay.validate_reason() == (True, "OK")
    final_root = _shadow(replay, "replay-final")
    print("[GREEN] full canonical replay preserves tip, UTXO, issuance, chainwork, and native shadow root")

    assert shadow_states >= 220, shadow_states
    print(f"RUST-005 shadow states checked: {shadow_states}")
    print(f"RUST-005 final sparse shadow root: {final_root}")
    print("RUST-005 replay/shadow equivalence: GREEN")


if __name__ == "__main__":
    main()
