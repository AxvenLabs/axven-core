#!/usr/bin/env python3
"""SEC-196: bound future block timestamps before they can poison retarget history."""

from types import SimpleNamespace

import axven

NOW = 2_000_000_000
EXPECTED_FUTURE_BOUND = 120


def _remine(block):
    block.nonce = 0
    while not block.pow_ok():
        block.nonce += 1


def _candidate_with_timestamp(timestamp):
    chain = axven.Blockchain()
    miner = axven.Wallet().address
    original_time = axven.time.time
    axven.time.time = lambda: NOW
    try:
        block = chain.build_candidate(miner)
    finally:
        axven.time.time = original_time
    block.timestamp = timestamp
    _remine(block)
    return chain, block


def _add_with_fixed_clock(chain, block):
    original_time = axven.time.time
    axven.time.time = lambda: NOW
    try:
        return chain.add_block(block)
    finally:
        axven.time.time = original_time


def main():
    # The existing retarget clamp limits one poisoned epoch to 4x easier
    # difficulty, but without a future-time admission bound an attacker can
    # place an arbitrarily future-dated epoch-end block into accepted history.
    prev_target = axven.MAX_TARGET // 16
    path = [
        SimpleNamespace(
            timestamp=NOW - axven.TARGET_TIMESPAN + i * axven.TARGET_BLOCK_TIME,
            target=prev_target,
        )
        for i in range(axven.ADJUST_INTERVAL)
    ]
    path[-1].timestamp = NOW + axven.TARGET_TIMESPAN * 100
    poisoned_target = axven.next_target_for_height(path, axven.ADJUST_INTERVAL)
    assert poisoned_target == prev_target * axven.RETARGET_CLAMP
    print("[GREEN] poisoned epoch-end timestamp can drive the full retarget easing clamp")

    future_bound = getattr(axven, "MAX_FUTURE_BLOCK_TIME", EXPECTED_FUTURE_BOUND)
    assert future_bound == EXPECTED_FUTURE_BOUND

    # A block just one second past the configured clock-skew allowance must
    # fail before its timestamp can become retarget input.
    chain, future_block = _candidate_with_timestamp(NOW + future_bound + 1)
    ok, reason = _add_with_fixed_clock(chain, future_block)
    assert not ok and "future" in reason.lower(), (
        "future-dated block entered accepted history: " + repr(reason)
    )
    assert chain.tip.height == 0
    print("[GREEN] excessive future timestamp rejected before chain mutation")

    # Keep a small deterministic skew allowance so ordinary clock drift does
    # not become a liveness failure.
    chain, boundary_block = _candidate_with_timestamp(NOW + future_bound)
    ok, reason = _add_with_fixed_clock(chain, boundary_block)
    assert ok, reason
    assert chain.tip.height == 1
    print("[GREEN] configured future-skew boundary remains accepted")

    # Existing MTP protection must remain intact.
    chain, stale_block = _candidate_with_timestamp(axven.GENESIS_TIME)
    ok, reason = _add_with_fixed_clock(chain, stale_block)
    assert not ok and "mtp" in reason.lower(), reason
    print("[GREEN] median-time-past lower bound remains enforced")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    print("[GREEN] canonical chain identity unchanged")

    print("SEC-196 time-warp/difficulty timestamp bound: 5/5 GREEN")


if __name__ == "__main__":
    main()
