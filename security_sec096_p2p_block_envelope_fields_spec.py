#!/usr/bin/env python3
"""SEC-096 rejects non-canonical P2P block message envelope fields."""

import p2p


CANONICAL_MINER = "N" + ("0" * 40)


class FakeBlock:
    def hash(self):
        return "f" * 64


class FakeChain:
    def __init__(self):
        self.add_calls = 0

    def add_block(self, block):
        self.add_calls += 1
        return False, "duplicate"


def raw_block():
    return {
        "height": 1,
        "timestamp": 1,
        "previous_hash": "0" * 64,
        "merkle_root": "0" * 64,
        "target": 1,
        "transactions": [],
        "nonce": 0,
        "miner": CANONICAL_MINER,
        "utxo_state_root": "0" * 64,
    }


def expect_rejected(session, message, expected):
    try:
        session.handle(message)
    except p2p.ProtocolError as exc:
        assert str(exc) == expected, exc
        return
    raise AssertionError(f"non-canonical envelope accepted: {message!r}")


def main():
    checks = 0
    chain = FakeChain()
    session = p2p.PeerSession(chain)
    deserialize_calls = [0]
    original_from_dict = p2p.axven.Block.__dict__["from_dict"]

    def fake_from_dict(cls, raw):
        deserialize_calls[0] += 1
        return FakeBlock()

    p2p.axven.Block.from_dict = classmethod(fake_from_dict)
    try:
        expect_rejected(
            session,
            {"type": "block", "block": raw_block(), "unexpected": True},
            "unknown block message field",
        )
        assert deserialize_calls[0] == 0
        assert chain.add_calls == 0
        checks += 1
        print("[GREEN] standalone block envelope rejects unknown fields")

        expect_rejected(
            session,
            {"type": "blocks", "blocks": [raw_block()], "unexpected": 1},
            "unknown blocks message field",
        )
        assert deserialize_calls[0] == 0
        assert chain.add_calls == 0
        checks += 1
        print("[GREEN] block batch envelope rejects unknown fields")

        reply = session.handle({"type": "block", "block": raw_block()})
        assert reply["type"] == "accepted"
        assert reply["kind"] == "block"
        assert deserialize_calls[0] == 1
        assert chain.add_calls == 1
        checks += 1
        print("[GREEN] canonical standalone block envelope preserved")

        reply = session.handle({"type": "blocks", "blocks": [raw_block()]})
        assert reply == {"type": "accepted", "kind": "blocks", "count": 1}
        assert deserialize_calls[0] == 2
        assert chain.add_calls == 2
        checks += 1
        print("[GREEN] canonical block batch envelope preserved")

        print(f"SEC-096 P2P block envelope fields: {checks}/{checks} GREEN")
    finally:
        p2p.axven.Block.from_dict = original_from_dict


if __name__ == "__main__":
    main()
