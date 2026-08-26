#!/usr/bin/env python3
"""SEC-065 canonical P2P block numeric field contract."""

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


def expect_numeric_reject(session, message, expected_error, deserialize_calls):
    before = deserialize_calls[0]
    try:
        session.handle(message)
    except p2p.ProtocolError as exc:
        assert str(exc) == expected_error, (
            f"unexpected P2P rejection: {exc}"
        )
        assert deserialize_calls[0] == before, (
            "invalid numeric field reached Block.from_dict"
        )
        return
    raise AssertionError("invalid block numeric field was accepted")


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
        invalid_cases = (
            ("height", "1", "block height must be integer"),
            ("timestamp", 1.0, "block timestamp must be integer"),
            ("target", True, "block target must be integer"),
            ("nonce", "0", "block nonce must be integer"),
        )

        for field, value, error in invalid_cases:
            raw = raw_block()
            raw[field] = value
            expect_numeric_reject(
                session,
                {"type": "block", "block": raw},
                error,
                deserialize_calls,
            )
            checks += 1
            print(f"[GREEN] single block rejects non-integer {field}")

        for field, value, error in invalid_cases:
            raw = raw_block()
            raw[field] = value
            expect_numeric_reject(
                session,
                {"type": "blocks", "blocks": [raw]},
                error,
                deserialize_calls,
            )
            checks += 1
            print(f"[GREEN] block batch rejects non-integer {field}")

        canonical = raw_block()
        reply = session.handle({"type": "block", "block": canonical})
        assert reply["type"] == "accepted"
        assert reply["kind"] == "block"
        assert deserialize_calls[0] == 1
        assert chain.add_calls == 1
        checks += 1
        print("[GREEN] canonical integer single block reaches deserialization")

        canonical = raw_block()
        reply = session.handle({"type": "blocks", "blocks": [canonical]})
        assert reply == {"type": "accepted", "kind": "blocks", "count": 1}
        assert deserialize_calls[0] == 2
        assert chain.add_calls == 2
        checks += 1
        print("[GREEN] canonical integer block batch reaches deserialization")

        legacy_optional_nonce = raw_block()
        legacy_optional_nonce.pop("nonce")
        reply = session.handle({"type": "block", "block": legacy_optional_nonce})
        assert reply["type"] == "accepted"
        assert reply["kind"] == "block"
        assert deserialize_calls[0] == 3
        assert chain.add_calls == 3
        checks += 1
        print("[GREEN] omitted optional nonce remains compatible")

    finally:
        p2p.axven.Block.from_dict = original_from_dict

    print(f"SEC-065 P2P block numeric types: {checks}/11 GREEN")


if __name__ == "__main__":
    main()
