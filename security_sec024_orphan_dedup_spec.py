#!/usr/bin/env python3
"""SEC-024 orphan block deduplication regression contract."""

import axven


def orphan_count(chain):
    return sum(len(v) for v in chain.orphans.values())


def main():
    chain = axven.Blockchain()

    orphan = axven.Block(
        height=1,
        timestamp=1,
        previous_hash="11" * 32,
        merkle_root=axven.merkle_root([]),
        target=axven.MAX_TARGET,
        transactions=[],
        nonce=0,
        miner="",
        utxo_state_root="",
    )

    ok, status = chain.add_block(orphan)
    assert not ok and status == "orphan"

    ok, status = chain.add_block(orphan)
    assert not ok and status in ("duplicate orphan", "orphan")

    count = orphan_count(chain)
    assert count == 1, f"duplicate orphan retained {count} copies"

    bucket = chain.orphans.get(orphan.previous_hash, [])
    assert len(bucket) == 1, f"orphan bucket retained {len(bucket)} copies"

    print("[GREEN] duplicate orphan does not consume another pool slot")

    # Repeating the same orphan must never fill the bounded pool.
    for _ in range(axven.MAX_ORPHAN_BLOCKS * 2):
        chain.add_block(orphan)

    assert orphan_count(chain) == 1
    print("[GREEN] repeated orphan cannot exhaust orphan pool")

    print("SEC-024 orphan block deduplication: 2/2 GREEN")


if __name__ == "__main__":
    main()
