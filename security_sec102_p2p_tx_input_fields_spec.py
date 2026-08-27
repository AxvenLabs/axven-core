#!/usr/bin/env python3
"""SEC-102 rejects non-canonical fields inside P2P transaction inputs."""

import copy

import axven
import p2p


class RecordingMempool:
    def __init__(self):
        self.add_calls = 0

    def add(self, tx):
        self.add_calls += 1
        return "sec102"


def expect_rejected(name, session, message):
    try:
        session.handle(message)
    except p2p.ProtocolError as exc:
        assert str(exc) == "unknown tx input field", exc
        print(f"[GREEN] {name}")
        return
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        raise AssertionError(
            f"{name}: malformed transaction input escaped as {type(exc).__name__}"
        ) from exc
    raise AssertionError(name)


def canonical_block():
    source = axven.Blockchain()
    miner = axven.Wallet()
    return source.build_candidate(miner.address).to_dict()


def main():
    checks = 0

    mempool = RecordingMempool()
    session = p2p.PeerSession(axven.Blockchain(), mempool)
    raw_tx = {
        "inputs": [
            {
                "prev_txid": "11" * 32,
                "index": 0,
                "signature": "",
                "public_key": "",
                "metadata": {"ignored": True},
            }
        ],
        "outputs": [{"amount": 1, "recipient": "N" + "0" * 40}],
    }
    expect_rejected(
        "standalone tx input unknown field rejected",
        session,
        {"type": "tx", "tx": raw_tx},
    )
    assert mempool.add_calls == 0, "malformed tx reached mempool"
    checks += 1

    raw = canonical_block()
    raw["transactions"][0]["inputs"][0]["metadata"] = {"ignored": True}
    expect_rejected(
        "coinbase tx input unknown field rejected",
        p2p.PeerSession(axven.Blockchain()),
        {"type": "block", "block": raw},
    )
    checks += 1

    raw = canonical_block()
    raw["transactions"][0]["inputs"][0]["ml_signature"] = ""
    expect_rejected(
        "coinbase known-but-noncanonical input field rejected",
        p2p.PeerSession(axven.Blockchain()),
        {"type": "blocks", "blocks": [raw]},
    )
    checks += 1

    healthy = canonical_block()
    reply = p2p.PeerSession(axven.Blockchain()).handle(
        {"type": "block", "block": copy.deepcopy(healthy)}
    )
    assert reply["type"] == "accepted"
    assert reply["kind"] == "block"
    checks += 1
    print("[GREEN] canonical coinbase input preserved")

    print(f"SEC-102 P2P tx input canonical fields: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
