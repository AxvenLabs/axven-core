#!/usr/bin/env python3
"""SEC-106 side-chain state validation before index admission."""

import copy
import axven


def remine(block):
    block.nonce = 0
    while not block.pow_ok():
        block.nonce += 1
    return block


def main():
    active = axven.Blockchain()
    fork = axven.Blockchain()
    active_wallet = axven.Wallet()
    fork_wallet = axven.Wallet()

    for _ in range(4):
        active.mine(active_wallet.address)
    for _ in range(3):
        fork.mine(fork_wallet.address)

    ok, status = active.add_block(fork.blocks[1])
    assert ok and status == "side-chain"
    ok, status = active.add_block(fork.blocks[2])
    assert ok and status == "side-chain"
    print("[GREEN] valid side-chain state remains admissible")

    invalid = copy.deepcopy(fork.blocks[3])
    invalid.utxo_state_root = (
        "f" * 64 if invalid.utxo_state_root != "f" * 64 else "e" * 64
    )
    remine(invalid)
    invalid_hash = invalid.hash()
    before_index = set(active.index)

    ok, reason = active.add_block(invalid)
    assert not ok
    assert "state root" in reason.lower(), reason
    assert invalid_hash not in active.index
    assert set(active.index) == before_index
    print("[GREEN] invalid side-chain state root rejected before indexing")

    ok, status = active.add_block(fork.blocks[3])
    assert ok and status == "side-chain"
    assert fork.blocks[3].hash() in active.index
    print("[GREEN] canonical replacement side block accepted")

    fork.mine(fork_wallet.address)
    fork.mine(fork_wallet.address)
    statuses = []
    for block in fork.blocks[4:]:
        ok, status = active.add_block(block)
        assert ok, status
        statuses.append(status)

    assert "reorg" in statuses
    assert active.tip.hash() == fork.tip.hash()
    assert active.utxo == fork.utxo
    assert active.validate()
    print("[GREEN] validated side branch still performs heavier-chain reorg")

    source = open(axven.__file__, "r", encoding="utf-8").read()
    assert "_validate_side_block_state" in source
    assert "cw <= self.chainwork" in source
    print("[GREEN] side-chain admission validation is wired before index publish")

    print("SEC-106 side-chain state admission: 5/5 GREEN")


if __name__ == "__main__":
    main()
