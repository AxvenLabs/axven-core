#!/usr/bin/env python3
"""SEC-016 bounded P2P sync request regression contract."""

import axven
import p2p


MAX_SYNC_BLOCKS = 128
MAX_LOCATOR_HASHES = 64


def main():
    checks = []

    def ok(name, condition):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    def rejected(name, session, msg):
        try:
            session.handle(msg)
        except p2p.ProtocolError:
            checks.append(name)
            print(f"[GREEN] {name}")
            return
        raise AssertionError(name)

    wallet = axven.Wallet()
    chain = axven.Blockchain()

    for _ in range(10):
        chain.mine(wallet.address)

    session = p2p.PeerSession(chain)

    locator = [chain.blocks[0].hash()]

    rejected(
        "zero get_blocks limit rejected",
        session,
        {
            "type": "get_blocks",
            "locator": locator,
            "limit": 0,
        },
    )

    rejected(
        "negative get_blocks limit rejected",
        session,
        {
            "type": "get_blocks",
            "locator": locator,
            "limit": -1,
        },
    )

    rejected(
        "oversized get_blocks limit rejected",
        session,
        {
            "type": "get_blocks",
            "locator": locator,
            "limit": MAX_SYNC_BLOCKS + 1,
        },
    )

    rejected(
        "oversized locator rejected",
        session,
        {
            "type": "get_blocks",
            "locator": ["00" * 32] * (MAX_LOCATOR_HASHES + 1),
            "limit": 1,
        },
    )

    rejected(
        "non-list locator rejected",
        session,
        {
            "type": "get_blocks",
            "locator": "00" * 32,
            "limit": 1,
        },
    )

    reply = session.handle(
        {
            "type": "get_blocks",
            "locator": locator,
            "limit": MAX_SYNC_BLOCKS,
        }
    )

    ok(
        "maximum valid sync limit accepted",
        reply["type"] == "blocks"
        and len(reply["blocks"]) <= MAX_SYNC_BLOCKS,
    )

    print(f"SEC-016 bounded P2P sync request: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
