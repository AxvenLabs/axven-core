#!/usr/bin/env python3
"""SEC-070 P2P transaction scheme/auth string budget contract."""

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
        return "d" * 64


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
    raise AssertionError("oversized transaction auth string reached admission")


def expect_accept(session, raw, deserialize_calls, mempool):
    before_deserialize = deserialize_calls[0]
    before_add = mempool.add_calls
    reply = session.handle({"type": "tx", "tx": raw})
    assert reply == {"type": "accepted", "kind": "tx", "id": "d" * 64}
    assert deserialize_calls[0] == before_deserialize + 1
    assert mempool.add_calls == before_add + 1


def main():
    checks = 0
    assert p2p_tx_bounds.MAX_P2P_TX_SCHEME_CHARS == 32
    checks += 1
    print("[GREEN] P2P tx scheme budget pinned at 32 chars")

    assert p2p_tx_bounds.MAX_P2P_TX_AUTH_CHARS == 8192
    checks += 1
    print("[GREEN] P2P tx auth budget pinned at 8192 chars")

    mempool = FakeMempool()
    session = p2p.PeerSession(FakeChain(), mempool)
    deserialize_calls = [0]
    original_from_dict = p2p.axven.Transaction.__dict__["from_dict"]

    def fake_from_dict(cls, raw):
        deserialize_calls[0] += 1
        return FakeTx()

    p2p.axven.Transaction.from_dict = classmethod(fake_from_dict)
    try:
        oversized_scheme = raw_tx()
        oversized_scheme["inputs"][0]["scheme"] = "s" * 33
        expect_reject(
            session,
            oversized_scheme,
            "tx input scheme too long",
            deserialize_calls,
            mempool,
        )
        checks += 1
        print("[GREEN] 33-char scheme rejected before deserialization")

        boundary_scheme = raw_tx()
        boundary_scheme["inputs"][0]["scheme"] = "s" * 32
        expect_accept(session, boundary_scheme, deserialize_calls, mempool)
        checks += 1
        print("[GREEN] 32-char scheme passes P2P budget")

        auth_fields = (
            "signature",
            "public_key",
            "ed_signature",
            "ed_public_key",
            "ml_signature",
            "ml_public_key",
        )
        for field in auth_fields:
            raw = raw_tx()
            raw["inputs"][0][field] = "x" * 8193
            expect_reject(
                session,
                raw,
                f"tx input {field} too long",
                deserialize_calls,
                mempool,
            )
            checks += 1
            print(f"[GREEN] 8193-char {field} rejected before deserialization")

        boundary_auth = raw_tx()
        boundary_auth["inputs"][0]["ml_signature"] = "x" * 8192
        expect_accept(session, boundary_auth, deserialize_calls, mempool)
        checks += 1
        print("[GREEN] 8192-char auth field passes P2P budget")

        canonical = raw_tx()
        canonical["inputs"][0].update(
            {
                "scheme": "hybrid",
                "ed_signature": "ed-sig",
                "ed_public_key": "ed-pub",
                "ml_signature": "ml-sig",
                "ml_public_key": "ml-pub",
            }
        )
        expect_accept(session, canonical, deserialize_calls, mempool)
        checks += 1
        print("[GREEN] canonical short scheme/auth strings remain compatible")
    finally:
        p2p.axven.Transaction.from_dict = original_from_dict

    print(f"SEC-070 P2P tx auth bounds: {checks}/12 GREEN")


if __name__ == "__main__":
    main()
