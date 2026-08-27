#!/usr/bin/env python3
"""SEC-079 aggregate orphan-pool byte budget contract."""
from __future__ import annotations

import axven


def check(condition, message, state):
    if not condition:
        raise AssertionError(message)
    state[0] += 1
    print(f"[GREEN] {message}")


def fake_orphan(i: int) -> axven.Block:
    return axven.Block(
        height=i + 1,
        timestamp=i + 1,
        previous_hash=axven.sha256(f"missing-parent-{i}".encode()),
        merkle_root=axven.EMPTY_ROOT,
        target=axven.MAX_TARGET,
        transactions=[],
        nonce=i,
        miner="",
        utxo_state_root="",
    )


def main():
    checks = [0]
    check(axven.MAX_ORPHAN_BYTES == 64 * 1024 * 1024,
          "aggregate orphan byte budget pinned at 64 MiB", checks)

    original_size = axven.serialized_block_size
    try:
        unit = 4 * 1024 * 1024
        axven.serialized_block_size = lambda _block: unit
        chain = axven.Blockchain()
        retained = []
        for i in range(16):
            block = fake_orphan(i)
            retained.append(block)
            ok, reason = chain.add_block(block)
            assert not ok and reason == "orphan"
        check(chain.orphan_bytes == axven.MAX_ORPHAN_BYTES,
              "exact aggregate byte budget remains admissible", checks)

        before_count = sum(len(v) for v in chain.orphans.values())
        before_bytes = chain.orphan_bytes
        ok, reason = chain.add_block(fake_orphan(1000))
        check(not ok and reason == "orphan byte budget full",
              "aggregate byte overflow rejected before retention", checks)
        check(sum(len(v) for v in chain.orphans.values()) == before_count
              and chain.orphan_bytes == before_bytes,
              "rejected aggregate overflow leaves orphan accounting unchanged", checks)

        ok, reason = chain.add_block(retained[0])
        check(not ok and reason == "duplicate orphan"
              and chain.orphan_bytes == before_bytes,
              "duplicate orphan consumes no additional byte budget", checks)

        axven.serialized_block_size = lambda _block: 1
        count_chain = axven.Blockchain()
        for i in range(axven.MAX_ORPHAN_BLOCKS):
            ok, reason = count_chain.add_block(fake_orphan(2000 + i))
            assert not ok and reason == "orphan"
        ok, reason = count_chain.add_block(fake_orphan(9999))
        check(not ok and reason == "orphan pool full",
              "existing 256-orphan count bound remains intact", checks)
    finally:
        axven.serialized_block_size = original_size

    wallet = axven.Wallet()
    shadow = axven.Blockchain()
    parent = shadow.build_candidate(wallet.address)
    ok, _ = shadow.add_block(parent)
    assert ok
    child = shadow.build_candidate(wallet.address)

    chain = axven.Blockchain()
    child_bytes = axven.serialized_block_size(child)
    ok, reason = chain.add_block(child)
    check(not ok and reason == "orphan" and chain.orphan_bytes == child_bytes,
          "retained orphan records its serialized byte cost", checks)

    ok, status = chain.add_block(parent)
    check(ok and status == "extended" and chain.tip.hash() == child.hash(),
          "parent arrival connects the retained orphan", checks)
    check(chain.orphan_bytes == 0 and not chain.orphan_sizes
          and sum(len(v) for v in chain.orphans.values()) == 0,
          "orphan connection releases aggregate byte accounting", checks)

    check(chain.validate(),
          "chain remains valid after orphan accounting release", checks)

    assert checks[0] == 10
    print(f"SEC-079 orphan aggregate byte budget: {checks[0]}/10 GREEN")


if __name__ == "__main__":
    main()
