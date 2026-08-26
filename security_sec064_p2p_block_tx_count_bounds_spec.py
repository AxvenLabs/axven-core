#!/usr/bin/env python3
"""SEC-064: P2P blocks must be bounded by the consensus transaction-count cap."""

import axven
import p2p


class DummyBlock:
    def hash(self):
        return "1" * 64


class FakeChain:
    def __init__(self):
        self.added = 0

    def add_block(self, block):
        self.added += 1
        return True, "accepted"


def raw_block(tx_count):
    return {
        "height": 1,
        "timestamp": 1,
        "previous_hash": "0" * 64,
        "merkle_root": "0" * 64,
        "target": axven.MAX_TARGET,
        "transactions": [{} for _ in range(tx_count)],
        "nonce": 0,
        "miner": "N" + ("0" * 40),
        "utxo_state_root": "0" * 64,
    }


def expect_too_many(session, message):
    try:
        session.handle(message)
    except p2p.ProtocolError as exc:
        assert str(exc) == "too many block transactions", (
            f"unexpected P2P rejection: {exc}"
        )
        return
    raise AssertionError("oversized block transaction list was accepted")


def main():
    checks = 0

    assert axven.MAX_BLOCK_TXS == 1000, (
        f"unexpected consensus block transaction cap: {axven.MAX_BLOCK_TXS}"
    )
    checks += 1
    print("[GREEN] consensus block transaction cap pinned at 1000")

    chain = FakeChain()
    session = p2p.PeerSession(chain)

    original_from_dict = axven.Block.__dict__["from_dict"]
    parsed = []

    def fake_from_dict(cls, raw):
        parsed.append(len(raw["transactions"]))
        return DummyBlock()

    axven.Block.from_dict = classmethod(fake_from_dict)

    try:
        before_parsed = len(parsed)
        before_added = chain.added
        expect_too_many(
            session,
            {
                "type": "block",
                "block": raw_block(axven.MAX_BLOCK_TXS + 1),
            },
        )
        assert len(parsed) == before_parsed, (
            "oversized single block reached Block.from_dict"
        )
        assert chain.added == before_added, (
            "oversized single block reached chain admission"
        )
        checks += 1
        print("[GREEN] oversized single block rejected before deserialization")

        response = session.handle(
            {
                "type": "block",
                "block": raw_block(axven.MAX_BLOCK_TXS),
            }
        )
        assert response["type"] == "accepted"
        assert response["kind"] == "block"
        assert parsed[-1] == axven.MAX_BLOCK_TXS
        checks += 1
        print("[GREEN] single block at consensus tx cap passes P2P preflight")

        before_parsed = len(parsed)
        before_added = chain.added
        expect_too_many(
            session,
            {
                "type": "blocks",
                "blocks": [raw_block(axven.MAX_BLOCK_TXS + 1)],
            },
        )
        assert len(parsed) == before_parsed, (
            "oversized batch block reached Block.from_dict"
        )
        assert chain.added == before_added, (
            "oversized batch block reached chain admission"
        )
        checks += 1
        print("[GREEN] oversized batch block rejected before deserialization")

        response = session.handle(
            {
                "type": "blocks",
                "blocks": [raw_block(axven.MAX_BLOCK_TXS)],
            }
        )
        assert response == {
            "type": "accepted",
            "kind": "blocks",
            "count": 1,
        }
        assert parsed[-1] == axven.MAX_BLOCK_TXS
        checks += 1
        print("[GREEN] batch block at consensus tx cap passes P2P preflight")

    finally:
        axven.Block.from_dict = original_from_dict

    print(
        f"SEC-064 P2P block transaction count bounds: "
        f"{checks}/5 GREEN"
    )


if __name__ == "__main__":
    main()
