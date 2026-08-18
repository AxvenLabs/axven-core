#!/usr/bin/env python3
"""SEC-023 bounded orphan block pool regression contract."""

import axven


EXPECTED_MAX_ORPHAN_BLOCKS = 256


def orphan_count(chain):
    return sum(len(v) for v in chain.orphans.values())


def make_orphan(tag):
    # Parent is deliberately unknown. The block does not need to be valid yet:
    # current orphan admission occurs before contextual validation.
    return axven.Block(
        height=1,
        timestamp=1,
        previous_hash=f"{tag:064x}",
        merkle_root="00" * 32,
        target=axven.MAX_TARGET,
        transactions=[],
        nonce=0,
        miner="",
        utxo_state_root="",
    )


def main():
    chain = axven.Blockchain()

    for i in range(EXPECTED_MAX_ORPHAN_BLOCKS + 64):
        block = make_orphan(i + 1)
        ok, status = chain.add_block(block)

        if ok:
            raise AssertionError("synthetic orphan unexpectedly accepted")

        if status not in ("orphan", "orphan pool full"):
            raise AssertionError(f"unexpected orphan status: {status}")

    count = orphan_count(chain)

    assert count <= EXPECTED_MAX_ORPHAN_BLOCKS, (
        f"orphan pool unbounded: retained {count}, "
        f"expected <= {EXPECTED_MAX_ORPHAN_BLOCKS}"
    )

    print(
        f"[GREEN] orphan pool bounded at {count}/"
        f"{EXPECTED_MAX_ORPHAN_BLOCKS}"
    )

    # Listener/node behavior must remain usable after saturation.
    valid_parent = chain.tip.hash()
    assert valid_parent in chain.index

    print("[GREEN] chain remains usable after orphan pool saturation")

    # Normal orphan resolution must still work: child first, parent later.
    source = axven.Blockchain()
    wallet = axven.Wallet()
    parent_block = source.mine(wallet.address)
    child_block = source.mine(wallet.address)

    target = axven.Blockchain()

    ok, status = target.add_block(child_block)
    assert not ok and status == "orphan"
    assert orphan_count(target) == 1
    print("[GREEN] valid child retained as orphan before parent")

    ok, status = target.add_block(parent_block)
    assert ok and status == "extended"
    assert target.tip.hash() == source.tip.hash()
    assert orphan_count(target) == 0
    assert target.validate()
    print("[GREEN] retained orphan connects when parent arrives")

    print("SEC-023 bounded orphan block pool: 4/4 GREEN")


if __name__ == "__main__":
    main()
