#!/usr/bin/env python3
"""SEC-095 rejects non-canonical top-level fields in P2P block payloads."""

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


def rejected(session, message, deserialize_calls):
    before = deserialize_calls[0]
    try:
        session.handle(message)
    except p2p.ProtocolError as exc:
        assert str(exc) == "unknown block field", exc
        assert deserialize_calls[0] == before, (
            "unknown P2P block field reached Block.from_dict"
        )
        return
    raise AssertionError("unknown P2P block field was accepted")


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
        single = raw_block()
        single["unexpected"] = "malleable"
        rejected(session, {"type": "block", "block": single}, deserialize_calls)
        checks += 1
        print("[GREEN] single block unknown top-level field rejected")

        batch = raw_block()
        batch["unexpected"] = 1
        rejected(session, {"type": "blocks", "blocks": [batch]}, deserialize_calls)
        checks += 1
        print("[GREEN] block batch unknown top-level field rejected")

        canonical = raw_block()
        reply = session.handle({"type": "block", "block": canonical})
        assert reply["type"] == "accepted"
        assert reply["kind"] == "block"
        assert deserialize_calls[0] == 1
        assert chain.add_calls == 1
        checks += 1
        print("[GREEN] canonical single block preserved")

        canonical_batch = raw_block()
        reply = session.handle({"type": "blocks", "blocks": [canonical_batch]})
        assert reply == {"type": "accepted", "kind": "blocks", "count": 1}
        assert deserialize_calls[0] == 2
        assert chain.add_calls == 2
        checks += 1
        print("[GREEN] canonical block batch preserved")

        optional_nonce = raw_block()
        optional_nonce.pop("nonce")
        reply = session.handle({"type": "block", "block": optional_nonce})
        assert reply["type"] == "accepted"
        assert deserialize_calls[0] == 3
        assert chain.add_calls == 3
        checks += 1
        print("[GREEN] legacy optional nonce preserved")

        print(f"SEC-095 P2P block canonical fields: {checks}/{checks} GREEN")
    finally:
        p2p.axven.Block.from_dict = original_from_dict


if __name__ == "__main__":
    main()
