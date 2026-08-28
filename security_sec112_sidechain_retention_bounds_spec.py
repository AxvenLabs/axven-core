#!/usr/bin/env python3
"""SEC-112 bounded side-chain retention against public fork-flood memory growth."""

import axven


def side_usage(chain):
    active_hashes = {block.hash() for block in chain.blocks}
    side_nodes = {
        block_hash: node
        for block_hash, node in chain.index.items()
        if block_hash not in active_hashes
    }
    side_bytes = sum(
        axven.serialized_block_size(node.block)
        for node in side_nodes.values()
    )
    return active_hashes, side_nodes, side_bytes


def mine_chain(count):
    chain = axven.Blockchain()
    wallet = axven.Wallet()
    for _ in range(count):
        chain.mine(wallet.address)
    return chain


def main():
    assert axven.MAX_SIDECHAIN_BLOCKS == 64
    assert axven.MAX_SIDECHAIN_BYTES == 64 * 1024 * 1024
    print("[GREEN] side-chain count and byte budgets pinned")

    old_count = axven.MAX_SIDECHAIN_BLOCKS
    old_bytes = axven.MAX_SIDECHAIN_BYTES
    try:
        axven.MAX_SIDECHAIN_BLOCKS = 2
        axven.MAX_SIDECHAIN_BYTES = 64 * 1024 * 1024

        active = mine_chain(5)
        fork_a = mine_chain(3)
        fork_b = mine_chain(1)
        active_hashes = {block.hash() for block in active.blocks}

        ok, status = active.add_block(fork_a.blocks[1])
        assert ok and status == "side-chain"
        ok, status = active.add_block(fork_a.blocks[2])
        assert ok and status == "side-chain"
        _active, side_nodes, _bytes = side_usage(active)
        assert len(side_nodes) == 2
        print("[GREEN] valid forks retained up to count budget")

        ok, status = active.add_block(fork_b.blocks[1])
        assert ok and status == "side-chain"
        current_active, side_nodes, side_bytes = side_usage(active)
        assert len(side_nodes) <= axven.MAX_SIDECHAIN_BLOCKS
        assert side_bytes <= axven.MAX_SIDECHAIN_BYTES
        assert fork_b.blocks[1].hash() in side_nodes
        assert active_hashes <= set(active.index)
        assert current_active == active_hashes
        print("[GREEN] unrelated side leaves pruned without touching active chain")

        ok, status = active.add_block(fork_a.blocks[2])
        assert ok and status == "side-chain"
        _active, side_nodes, side_bytes = side_usage(active)
        assert fork_a.blocks[1].hash() in side_nodes
        assert fork_a.blocks[2].hash() in side_nodes
        assert fork_b.blocks[1].hash() not in active.index
        assert len(side_nodes) <= axven.MAX_SIDECHAIN_BLOCKS
        assert side_bytes <= axven.MAX_SIDECHAIN_BYTES
        print("[GREEN] protected incoming fork ancestry survives pruning")

        active2 = mine_chain(2)
        fork2 = mine_chain(3)
        ok, status = active2.add_block(fork2.blocks[1])
        assert ok and status == "side-chain"
        ok, status = active2.add_block(fork2.blocks[2])
        assert ok and status == "side-chain"
        ok, status = active2.add_block(fork2.blocks[3])
        assert ok and status == "reorg"
        assert active2.tip.hash() == fork2.tip.hash()
        assert active2.validate()
        active2_hashes, side2, side2_bytes = side_usage(active2)
        assert active2_hashes <= set(active2.index)
        assert len(side2) <= axven.MAX_SIDECHAIN_BLOCKS
        assert side2_bytes <= axven.MAX_SIDECHAIN_BYTES
        print("[GREEN] heavier valid fork still reorgs")

        active3 = mine_chain(3)
        fork3 = mine_chain(2)
        first_size = axven.serialized_block_size(fork3.blocks[1])
        second_size = axven.serialized_block_size(fork3.blocks[2])
        axven.MAX_SIDECHAIN_BLOCKS = 64
        axven.MAX_SIDECHAIN_BYTES = first_size + second_size - 1
        ok, status = active3.add_block(fork3.blocks[1])
        assert ok and status == "side-chain"
        before_index = set(active3.index)
        ok, reason = active3.add_block(fork3.blocks[2])
        assert not ok and "retention budget" in reason
        assert set(active3.index) == before_index
        _active, side3, side3_bytes = side_usage(active3)
        assert len(side3) <= axven.MAX_SIDECHAIN_BLOCKS
        assert side3_bytes <= axven.MAX_SIDECHAIN_BYTES
        print("[GREEN] protected fork cannot exceed byte budget")
    finally:
        axven.MAX_SIDECHAIN_BLOCKS = old_count
        axven.MAX_SIDECHAIN_BYTES = old_bytes

    source_text = open(axven.__file__, "r", encoding="utf-8").read()
    assert "_prune_side_index_for_budget" in source_text
    assert "protected=protected" in source_text
    print("[GREEN] bounded retention wired before side index publish")
    print("SEC-112 bounded side-chain retention: 6/6 GREEN")


if __name__ == "__main__":
    main()
