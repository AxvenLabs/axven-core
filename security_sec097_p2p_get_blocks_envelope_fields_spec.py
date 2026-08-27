#!/usr/bin/env python3
"""SEC-097 rejects non-canonical P2P get_blocks envelope fields."""

import threading

import p2p


class FakeBlock:
    def __init__(self, value):
        self.value = value

    def hash(self):
        return self.value

    def to_dict(self):
        return {"height": 0}


class FakeChain:
    def __init__(self):
        self._state_lock = threading.RLock()
        self.blocks = [FakeBlock("0" * 64)]


def rejected(session, message):
    try:
        session.handle(message)
    except p2p.ProtocolError as exc:
        assert str(exc) == "unknown get_blocks message field", exc
        return
    raise AssertionError("non-canonical get_blocks envelope accepted")


def main():
    checks = 0
    session = p2p.PeerSession(FakeChain())
    expected = {"type": "blocks", "blocks": [{"height": 0}]}

    rejected(
        session,
        {"type": "get_blocks", "locator": [], "limit": 1, "unexpected": True},
    )
    checks += 1
    print("[GREEN] get_blocks rejects unknown envelope field")

    reply = session.handle({"type": "get_blocks", "locator": [], "limit": 1})
    assert reply == expected
    checks += 1
    print("[GREEN] canonical get_blocks locator+limit preserved")

    reply = session.handle({"type": "get_blocks"})
    assert reply == expected
    checks += 1
    print("[GREEN] legacy optional locator/limit defaults preserved")

    try:
        session.handle({"type": "get_blocks", "locator": [], "limit": True})
    except p2p.ProtocolError as exc:
        assert str(exc) == "invalid block limit", exc
        checks += 1
        print("[GREEN] existing limit type guard preserved")
    else:
        raise AssertionError("boolean block limit accepted")

    print(f"SEC-097 P2P get_blocks envelope fields: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
