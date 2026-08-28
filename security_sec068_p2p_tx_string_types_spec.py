#!/usr/bin/env python3
"""SEC-068 canonical P2P transaction string field contract."""

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
        return "b" * 64


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


def hybrid_tx():
    raw = raw_tx()
    raw["inputs"][0] = {
        "prev_txid": "0" * 64,
        "index": 0,
        "scheme": "hybrid-ed25519+ml-dsa-44",
        "ed_signature": "ed-sig",
        "ed_public_key": "ed-pub",
        "ml_signature": "ml-sig",
        "ml_public_key": "ml-pub",
    }
    return raw


def raw_tx_for_field(field):
    if field in ("ed_signature", "ed_public_key", "ml_signature", "ml_public_key"):
        return hybrid_tx()
    return raw_tx()


def expect_reject(session, raw, expected_error, deserialize_calls, mempool):
    before_deserialize = deserialize_calls[0]
    before_add = mempool.add_calls
    try:
        session.handle({"type": "tx", "tx": raw})
    except p2p.ProtocolError as exc:
        assert str(exc) == expected_error, f"unexpected P2P rejection: {exc}"
        assert deserialize_calls[0] == before_deserialize, (
            "invalid string transaction field reached Transaction.from_dict"
        )
        assert mempool.add_calls == before_add, (
            "invalid string transaction field reached mempool"
        )
        return
    raise AssertionError("invalid transaction string field was accepted")


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
        for value in (0, True, None):
            raw = raw_tx()
            raw["inputs"][0]["prev_txid"] = value
            expect_reject(
                session,
                raw,
                "tx input prev_txid must be string",
                deserialize_calls,
                mempool,
            )
            checks += 1
            print(f"[GREEN] non-string tx prev_txid rejected: {value!r}")

        for value in (0, False, None):
            raw = raw_tx()
            raw["outputs"][0]["recipient"] = value
            expect_reject(
                session,
                raw,
                "tx output recipient must be string",
                deserialize_calls,
                mempool,
            )
            checks += 1
            print(f"[GREEN] non-string tx recipient rejected: {value!r}")

        optional_fields = (
            "scheme",
            "signature",
            "public_key",
            "ed_signature",
            "ed_public_key",
            "ml_signature",
            "ml_public_key",
        )
        for field in optional_fields:
            raw = raw_tx_for_field(field)
            raw["inputs"][0][field] = 123
            expect_reject(
                session,
                raw,
                f"tx input {field} must be string",
                deserialize_calls,
                mempool,
            )
            checks += 1
            print(f"[GREEN] non-string tx input {field} rejected")

        canonical = raw_tx()
        reply = session.handle({"type": "tx", "tx": canonical})
        assert reply == {
            "type": "accepted",
            "kind": "tx",
            "id": "b" * 64,
        }
        assert deserialize_calls[0] == 1
        assert mempool.add_calls == 1
        checks += 1
        print("[GREEN] canonical transaction string fields reach mempool")

        all_string_fields = hybrid_tx()
        reply = session.handle({"type": "tx", "tx": all_string_fields})
        assert reply == {
            "type": "accepted",
            "kind": "tx",
            "id": "b" * 64,
        }
        assert deserialize_calls[0] == 2
        assert mempool.add_calls == 2
        checks += 1
        print("[GREEN] canonical hybrid auth fields accept canonical strings")

    finally:
        p2p.axven.Transaction.from_dict = original_from_dict

    print(f"SEC-068 P2P transaction string types: {checks}/15 GREEN")


if __name__ == "__main__":
    main()
