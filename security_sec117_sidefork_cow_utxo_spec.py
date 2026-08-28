#!/usr/bin/env python3
"""SEC-117 bound tentative side/reorg UTXO copy amplification."""

import copy
import inspect
import axven


def mine_chain(count, wallet=None):
    chain = axven.Blockchain()
    wallet = wallet or axven.Wallet()
    for _ in range(count):
        chain.mine(wallet.address)
    return chain


def replay_prefix(chain, height):
    out = axven.Blockchain()
    for block in chain.blocks[1:height + 1]:
        ok, status = out.add_block(block)
        assert ok and status == "extended"
    return out


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

    base = {
        f"{i:064x}:0": {
            "amount": i + 1,
            "recipient": "N" + f"{i:040x}"[-40:],
            "coinbase": False,
            "height": 1,
        }
        for i in range(4096)
    }
    overlay = axven._UTXOOverlay(base)
    green(
        "overlay starts O(1) over live base",
        overlay._base is base and overlay.delta_size == 0 and len(overlay) == len(base),
    )

    expected = copy.deepcopy(base)
    spent = next(iter(base))
    new_op = "f" * 64 + ":1"
    old = overlay.pop(spent)
    expected.pop(spent)
    overlay[new_op] = {
        "amount": 777,
        "recipient": "N" + "a" * 40,
        "coinbase": False,
        "height": 2,
    }
    expected[new_op] = dict(overlay[new_op])
    green(
        "overlay mutations remain delta-sized and base-isolated",
        overlay.delta_size == 2 and spent in base and new_op not in base,
    )
    overlay[spent] = old
    expected[spent] = old
    materialized = overlay.materialize()
    green(
        "overlay materialization matches ordinary dict semantics",
        materialized == expected and type(materialized) is dict,
    )

    legacy_height = 9
    sparse_height = int(axven.CHAIN_CONFIG["smt_activation_height"])
    small_base = dict(list(base.items())[:32])
    small_overlay = axven._UTXOOverlay(small_base)
    small_overlay.pop(next(iter(small_base)))
    small_overlay[new_op] = expected[new_op]
    small_expected = small_overlay.materialize()
    green(
        "state-root oracle is identical for overlay and dict state",
        axven.expected_state_root(small_overlay, legacy_height)
        == axven.expected_state_root(small_expected, legacy_height)
        and axven.expected_state_root(small_overlay, sparse_height)
        == axven.expected_state_root(small_expected, sparse_height),
    )

    active = mine_chain(6)
    parent_height = active.tip.height - 1
    sibling_builder = replay_prefix(active, parent_height)
    sibling = sibling_builder.build_candidate(axven.Wallet().address)
    active_before = copy.deepcopy(active.utxo)

    class NoDeepcopy:
        @staticmethod
        def deepcopy(*_args, **_kwargs):
            raise AssertionError("tentative network fork path attempted deepcopy")

    old_copy_module = axven.copy
    axven.copy = NoDeepcopy()
    try:
        ok, status = active.add_block(sibling)
    finally:
        axven.copy = old_copy_module
    green(
        "valid non-winning side admission performs no full UTXO deepcopy",
        ok and status == "side-chain" and active.utxo == active_before,
    )

    bad_builder = replay_prefix(active, parent_height)
    bad_side = bad_builder.build_candidate(axven.Wallet().address)
    bad_side.utxo_state_root = "11" * 32
    remine(bad_side)
    active_before_bad = copy.deepcopy(active.utxo)
    old_copy_module = axven.copy
    axven.copy = NoDeepcopy()
    try:
        ok, reason = active.add_block(bad_side)
    finally:
        axven.copy = old_copy_module
    green(
        "invalid side state fails without copying or mutating live UTXO",
        (not ok)
        and "state root" in reason.lower()
        and active.utxo == active_before_bad,
    )

    active2 = mine_chain(2)
    fork2 = mine_chain(3)
    ok, status = active2.add_block(fork2.blocks[1])
    assert ok and status == "side-chain"
    ok, status = active2.add_block(fork2.blocks[2])
    assert ok and status == "side-chain"

    invalid_winner = copy.deepcopy(fork2.blocks[3])
    invalid_winner.utxo_state_root = "22" * 32
    remine(invalid_winner)
    before_tip = active2.tip.hash()
    before_utxo = copy.deepcopy(active2.utxo)
    old_copy_module = axven.copy
    axven.copy = NoDeepcopy()
    try:
        ok, reason = active2.add_block(invalid_winner)
    finally:
        axven.copy = old_copy_module
    green(
        "invalid heavier fork aborts without full UTXO deepcopy",
        (not ok)
        and "reorg aborted" in reason.lower()
        and active2.tip.hash() == before_tip
        and active2.utxo == before_utxo,
    )

    ok, status = active2.add_block(fork2.blocks[3])
    green(
        "valid heavier reorg still materializes exact plain-dict state",
        ok
        and status == "reorg"
        and type(active2.utxo) is dict
        and active2.utxo == fork2.utxo
        and active2.validate(),
    )

    state_src = inspect.getsource(axven.Blockchain._state_for_index_node)
    reorg_src = inspect.getsource(axven.Blockchain._reorg_to)
    green(
        "production tentative fork paths are wired to copy-on-write state",
        "_UTXOOverlay(self.utxo)" in state_src
        and "copy.deepcopy(self.utxo)" not in state_src
        and "_UTXOOverlay(self.utxo)" in reorg_src
        and "copy.deepcopy(self.utxo)" not in reorg_src
        and ".materialize()" in reorg_src,
    )

    print(f"SEC-117 side-fork COW UTXO: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
