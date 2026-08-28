#!/usr/bin/env python3
"""SEC-116 bounds side-fork active-chain traversal without changing context rules."""

import copy

import axven


def make_sibling(chain, wallet):
    tip = chain.tip
    height = tip.height
    assert height >= 2 and height % axven.ADJUST_INTERVAL != 0
    parent_hash = tip.previous_hash

    trial = copy.deepcopy(chain.utxo)
    tip_undo = chain.undo[tip.hash()]
    axven._undo_forward(tip_undo, trial)
    issued = chain.total_issued - tip_undo.reward

    coinbase = axven.make_coinbase(
        wallet.address,
        axven.block_reward(height, issued),
        height,
    )
    block = axven.Block(
        height=height,
        timestamp=tip.timestamp,
        previous_hash=parent_hash,
        merkle_root=axven.merkle_root([coinbase.txid()]),
        target=tip.target,
        transactions=[coinbase.to_dict()],
        nonce=0,
        miner=wallet.address,
        utxo_state_root="",
    )
    ok, reason, _undo, _reward, _fees = axven._transition(
        block, trial, height, issued
    )
    assert ok, reason
    block.utxo_state_root = axven.expected_state_root(trial, height)
    while not block.pow_ok():
        block.nonce += 1
    assert axven._check_context(block, chain.blocks[:height], height) is None
    return block


def main():
    checks = 0
    miner = axven.Wallet()
    chain = axven.Blockchain()
    for _ in range(32):
        chain.mine(miner.address)

    parent_hash = chain.tip.previous_hash
    parent_node = chain.index[parent_hash]
    view = chain._indexed_path_view(parent_node)
    legacy = chain._ancestry(parent_hash)
    assert len(view) == len(legacy)
    assert [b.hash() for b in view] == [b.hash() for b in legacy]
    checks += 1
    print("[GREEN] indexed active path preserves exact ancestry sequence")

    sibling = make_sibling(chain, axven.Wallet())
    side_hash = sibling.hash()
    checks += 1
    print("[GREEN] alternate near-tip block is context-valid before admission")

    historical = list(chain.blocks[:-16])
    try:
        def ancestry_forbidden(_):
            raise AssertionError("full ancestry materialization attempted")
        chain._ancestry = ancestry_forbidden

        for block in historical:
            height = block.height
            def forbidden_hash(height=height):
                raise AssertionError(
                    f"historical active hash scan attempted at height {height}"
                )
            block.hash = forbidden_hash

        ok, status = chain.add_block(sibling)
        assert ok and status == "side-chain", (ok, status)
    finally:
        if "_ancestry" in chain.__dict__:
            del chain.__dict__["_ancestry"]
        for block in historical:
            if "hash" in block.__dict__:
                del block.__dict__["hash"]
    checks += 1
    print("[GREEN] side admission avoids full ancestry and active hash scans")

    side_node = chain.index[side_hash]
    side_view = chain._indexed_path_view(side_node)
    side_legacy = chain._ancestry(side_hash)
    assert [b.hash() for b in side_view] == [b.hash() for b in side_legacy]
    checks += 1
    print("[GREEN] indexed side path preserves exact legacy ancestry sequence")

    side_nodes, side_sizes = chain._side_index_snapshot()
    assert set(side_nodes) == {side_hash}
    assert side_sizes == {side_hash: axven.serialized_block_size(sibling)}
    checks += 1
    print("[GREEN] retained side-node byte tracking is exact and bounded")

    assert chain.validate()
    checks += 1
    print("[GREEN] active chain remains consensus-valid after bounded side admission")

    source = open(axven.__file__, "r", encoding="utf-8").read()
    assert "path = self._indexed_path_view(parent_node)" in source
    assert "err = _check_context(block, path, height)" in source
    assert "active_hashes = {b.hash() for b in self.blocks}" not in source
    assert "self.side_sizes" in source
    checks += 1
    print("[GREEN] production wiring removes full-chain side-fork scans")

    assert checks == 7
    print("SEC-116 bounded side-fork path work: 7/7 GREEN")


if __name__ == "__main__":
    main()
