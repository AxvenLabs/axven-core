#!/usr/bin/env python3
"""SEC-069 P2P transaction identifier/address string budget contract."""

import p2p
import p2p_tx_bounds


class FakeTx:
    pass


class FakeChain:
    pass


class FakeMempool:
    def __init__(self):
        self.add_calls = 0

    def add(self, tx):
        self.add_calls += 1
        return "c" * 64


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
        assert deserialize_calls[0] == before_deserialize
        assert mempool.add_calls == before_add
        return
    raise AssertionError("oversized transaction string reached admission")


def expect_accept(session, raw, deserialize_calls, mempool):
    before_deserialize = deserialize_calls[0]
    before_add = mempool.add_calls
    reply = session.handle({"type": "tx", "tx": raw})
    assert reply == {"type": "accepted", "kind": "tx", "id": "c" * 64}
    assert deserialize_calls[0] == before_deserialize + 1
    assert mempool.add_calls == before_add + 1


def main():
    checks = 0
    assert p2p_tx_bounds.MAX_P2P_TXID_CHARS == 64
    checks += 1
    print("[GREEN] P2P txid budget pinned at 64 chars")

    assert p2p_tx_bounds.MAX_P2P_RECIPIENT_CHARS == 128
    checks += 1
    print("[GREEN] P2P recipient budget pinned at 128 chars")

    mempool = FakeMempool()
    session = p2p.PeerSession(FakeChain(), mempool)
    deserialize_calls = [0]
    original_from_dict = p2p.axven.Transaction.__dict__["from_dict"]

    def fake_from_dict(cls, raw):
        deserialize_calls[0] += 1
        return FakeTx()

    p2p.axven.Transaction.from_dict = classmethod(fake_from_dict)
    try:
        oversized_txid = raw_tx()
        oversized_txid["inputs"][0]["prev_txid"] = "0" * 65
        expect_reject(
            session,
            oversized_txid,
            "tx input prev_txid too long",
            deserialize_calls,
            mempool,
        )
        checks += 1
        print("[GREEN] 65-char prev_txid rejected before deserialization")

        boundary_txid = raw_tx()
        boundary_txid["inputs"][0]["prev_txid"] = "0" * 64
        expect_accept(session, boundary_txid, deserialize_calls, mempool)
        checks += 1
        print("[GREEN] 64-char prev_txid passes P2P budget")

        oversized_recipient = raw_tx()
        oversized_recipient["outputs"][0]["recipient"] = "N" * 129
        expect_reject(
            session,
            oversized_recipient,
            "tx output recipient too long",
            deserialize_calls,
            mempool,
        )
        checks += 1
        print("[GREEN] 129-char recipient rejected before deserialization")

        boundary_recipient = raw_tx()
        boundary_recipient["outputs"][0]["recipient"] = "N" * 128
        expect_accept(session, boundary_recipient, deserialize_calls, mempool)
        checks += 1
        print("[GREEN] 128-char recipient passes P2P budget")
    finally:
        p2p.axven.Transaction.from_dict = original_from_dict

    print(f"SEC-069 P2P tx identifier/address bounds: {checks}/6 GREEN")


if __name__ == "__main__":
    main()
