#!/usr/bin/env python3
"""SEC-017 bounded inbound P2P block-batch regression contract."""

import axven
import p2p


MAX_SYNC_BLOCKS = 128


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

    chain = axven.Blockchain()
    session = p2p.PeerSession(chain)

    rejected(
        "non-list blocks payload rejected",
        session,
        {
            "type": "blocks",
            "blocks": {},
        },
    )

    rejected(
        "oversized inbound block batch rejected",
        session,
        {
            "type": "blocks",
            "blocks": [{}] * (MAX_SYNC_BLOCKS + 1),
        },
    )

    reply = session.handle(
        {
            "type": "blocks",
            "blocks": [],
        }
    )

    ok(
        "empty inbound block batch accepted",
        reply == {
            "type": "accepted",
            "kind": "blocks",
            "count": 0,
        },
    )

    print(
        f"SEC-017 bounded inbound P2P block batch: "
        f"{len(checks)}/{len(checks)} GREEN"
    )


if __name__ == "__main__":
    main()
