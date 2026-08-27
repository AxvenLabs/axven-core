#!/usr/bin/env python3
"""SEC-084 requires explicit blocks payloads on P2P sync responses."""

import axven
import p2p


class _DummySock:
    def close(self):
        pass


def main():
    checks = []

    def rejected(name, fn):
        try:
            fn()
        except p2p.ProtocolError:
            checks.append(name)
            print(f"[GREEN] {name}")
            return
        raise AssertionError(name)

    chain = axven.Blockchain()
    session = p2p.PeerSession(chain)

    rejected(
        "missing blocks payload rejected",
        lambda: session.handle({"type": "blocks"}),
    )
    rejected(
        "null blocks payload rejected",
        lambda: session.handle({"type": "blocks", "blocks": None}),
    )
    rejected(
        "boolean blocks payload rejected",
        lambda: session.handle({"type": "blocks", "blocks": False}),
    )
    rejected(
        "object blocks payload rejected",
        lambda: session.handle({"type": "blocks", "blocks": {}}),
    )

    reply = session.handle({"type": "blocks", "blocks": []})
    assert reply == {"type": "accepted", "kind": "blocks", "count": 0}
    checks.append("explicit empty blocks payload accepted")
    print("[GREEN] explicit empty blocks payload accepted")

    original_connect = p2p.connect
    original_request = p2p.request
    try:
        p2p.connect = lambda address: _DummySock()

        p2p.request = lambda sock, msg: {"type": "blocks"}
        rejected(
            "sync path rejects missing blocks payload",
            lambda: p2p.sync_to_peer(("127.0.0.1", 1), session, max_rounds=1),
        )

        p2p.request = lambda sock, msg: {"type": "blocks", "blocks": None}
        rejected(
            "sync path rejects null blocks payload",
            lambda: p2p.sync_to_peer(("127.0.0.1", 1), session, max_rounds=1),
        )

        p2p.request = lambda sock, msg: {"type": "blocks", "blocks": []}
        assert p2p.sync_to_peer(("127.0.0.1", 1), session, max_rounds=1) == 0
        checks.append("sync path accepts explicit empty blocks payload")
        print("[GREEN] sync path accepts explicit empty blocks payload")
    finally:
        p2p.connect = original_connect
        p2p.request = original_request

    print(f"SEC-084 explicit P2P blocks payload: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
