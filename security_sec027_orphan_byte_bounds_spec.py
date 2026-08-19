import axven


def ok(name):
    print(f"[GREEN] {name}")


def make_oversized_orphan():
    # Unknown parent forces orphan admission path.
    # Inflate miner so the serialized block exceeds the canonical block cap
    # without requiring thousands of transaction objects.
    block = axven.Block(
        height=1,
        timestamp=1,
        previous_hash="1" * 64,
        merkle_root=axven.merkle_root([]),
        target=axven.MAX_TARGET,
        transactions=[],
        nonce=0,
        miner="X" * (int(axven.CHAIN_CONFIG["max_block_bytes"]) + 1024),
        utxo_state_root="",
    )
    return block


def main():
    chain = axven.Blockchain()
    block = make_oversized_orphan()

    size = axven.serialized_block_size(block)
    cap = int(axven.CHAIN_CONFIG["max_block_bytes"])

    assert size > cap, (
        f"test fixture not oversized: {size} <= {cap}"
    )

    accepted, reason = chain.add_block(block)

    retained = sum(len(v) for v in chain.orphans.values())

    assert not accepted

    assert retained == 0, (
        f"oversized orphan retained: "
        f"{size} bytes > {cap} byte cap; reason={reason!r}"
    )

    ok("oversized orphan rejected before retention")

    # Normal-sized orphan behavior must remain unchanged.
    normal = axven.Block(
        height=1,
        timestamp=1,
        previous_hash="2" * 64,
        merkle_root=axven.merkle_root([]),
        target=axven.MAX_TARGET,
        transactions=[],
        nonce=0,
        miner="",
        utxo_state_root="",
    )

    accepted, reason = chain.add_block(normal)

    assert not accepted
    assert reason == "orphan"

    retained = sum(len(v) for v in chain.orphans.values())
    assert retained == 1

    ok("normal-sized orphan admission preserved")

    print("SEC-027 orphan block byte admission: 2/2 GREEN")


if __name__ == "__main__":
    main()
