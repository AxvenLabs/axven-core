#!/usr/bin/env python3
"""SEC-099 canonical P2P get_status envelope regression contract."""

import threading

import p2p


class FakeTip:
    height = 7

    def hash(self):
        return "ab" * 32


class FakeChain:
    def __init__(self):
        self._state_lock = threading.RLock()
        self.tip = FakeTip()
        self.chainwork = 123


def rejected(session, message):
    try:
        session.handle(message)
    except p2p.ProtocolError as exc:
        assert str(exc) == "unknown get_status message field", exc
        return
    raise AssertionError("non-canonical get_status envelope accepted")


def main():
    session = p2p.PeerSession(FakeChain())

    for value in (None, True, 1, "x", [], {}, {"nested": [1, 2, 3]}):
        rejected(session, {"type": "get_status", "extension": value})
    print("[GREEN] get_status rejects unknown envelope fields")

    reply = session.handle({"type": "get_status"})
    assert reply == {
        "type": "status",
        "height": 7,
        "tip_hash": "ab" * 32,
        "chainwork": 123,
    }
    print("[GREEN] canonical get_status response preserved")
    print("SEC-099 canonical P2P get_status fields: 2/2 GREEN")


if __name__ == "__main__":
    main()
