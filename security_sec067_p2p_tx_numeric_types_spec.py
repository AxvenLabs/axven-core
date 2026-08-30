#!/usr/bin/env python3
"""SEC-067 canonical P2P transaction numeric field contract."""

import p2p


class FakeTx:
    pass


class FakeChain:
    pass


class FakeMempool:
    def __init__(self):
        self.add_calls = 0

    def add(self, tx):
        self.add_calls += 1
        return "a" * 64


def raw_tx():
    return {
        "inputs": [
            {
                "prev_txid": "0" * 64,
                "index": 0,
                "signature": "sig",
                "public_key": "pub",
            }
        ],
        "outputs": [
            {
                "amount": 1,
                "recipient": "N" + ("0" * 40),
            }
        ],
    }


def expect_reject(session, raw, expected_error, deserialize_calls, mempool):
    before_deserialize = deserialize_calls[0]
    before_add = mempool.add_calls
    try:
        session.handle({"type": "tx", "tx": raw})
    except p2p.ProtocolError as exc:
        assert str(exc) == expected_error, f"unexpected P2P rejection: {exc}"
        assert deserialize_calls[0] == before_deserialize, (
            "invalid numeric transaction field reached Transaction.from_dict"
        )
        assert mempool.add_calls == before_add, (
            "invalid numeric transaction field reached mempool"
        )
        return
    raise AssertionError("invalid transaction numeric field was accepted")


def main():
    checks = 0
    mempool = FakeMempool()
    session = p2p.PeerSession(FakeChain(), mempool)
    deserialize_calls = [0]

    original_from_dict = p2p.axven.Transaction.__dict__["from_dict"]

    def fake_from_dict(cls, raw):
        deserialize_calls[0] += 1
        return FakeTx()

    p2p.axven.Transaction.from_dict = classmethod(fake_from_dict)

    try:
        for value in ("0", 0.0, True):
            raw = raw_tx()
            raw["inputs"][0]["index"] = value
            expect_reject(
                session,
                raw,
                "tx input index must be integer",
                deserialize_calls,
                mempool,
            )
            checks += 1
            print(f"[GREEN] non-integer tx input index rejected: {value!r}")

        for value in ("1", 1.0, True):
            raw = raw_tx()
            raw["outputs"][0]["amount"] = value
            expect_reject(
                session,
                raw,
                "tx output amount must be integer",
                deserialize_calls,
                mempool,
            )
            checks += 1
            print(f"[GREEN] non-integer tx output amount rejected: {value!r}")

        for value in ("1", 1.0, True, None):
            raw = raw_tx()
            raw["coinbase_height"] = value
            expect_reject(
                session,
                raw,
                "tx coinbase_height must be integer",
                deserialize_calls,
                mempool,
            )
            checks += 1
            print(f"[GREEN] non-integer tx coinbase_height rejected: {value!r}")

        regular_with_height = raw_tx()
        regular_with_height["coinbase_height"] = 1
        expect_reject(
            session,
            regular_with_height,
            "coinbase height forbidden on regular tx",
            deserialize_calls,
            mempool,
        )
        checks += 1
        print("[GREEN] integer coinbase_height rejected on regular transaction")

        canonical = raw_tx()
        reply = session.handle({"type": "tx", "tx": canonical})
        assert reply == {
            "type": "accepted",
            "kind": "tx",
            "id": "a" * 64,
        }
        assert deserialize_calls[0] == 1
        assert mempool.add_calls == 1
        checks += 1
        print("[GREEN] canonical regular transaction omits coinbase_height")

    finally:
        p2p.axven.Transaction.from_dict = original_from_dict

    print(f"SEC-067 P2P transaction numeric types: {checks}/12 GREEN")


if __name__ == "__main__":
    main()
