#!/usr/bin/env python3
"""SEC-085 requires explicit P2P transaction input/output fields."""

import axven
import p2p


class _RecordingMempool:
    def __init__(self):
        self.last_tx = None

    def add(self, tx):
        self.last_tx = tx
        return "sec085"


def main():
    checks = []

    def rejected(name, session, msg):
        try:
            session.handle(msg)
        except p2p.ProtocolError:
            checks.append(name)
            print(f"[GREEN] {name}")
            return
        raise AssertionError(name)

    chain = axven.Blockchain()
    mempool = _RecordingMempool()
    session = p2p.PeerSession(chain, mempool)

    rejected(
        "missing tx inputs rejected",
        session,
        {"type": "tx", "tx": {"outputs": []}},
    )
    rejected(
        "missing tx outputs rejected",
        session,
        {"type": "tx", "tx": {"inputs": []}},
    )
    rejected(
        "missing tx vectors rejected",
        session,
        {"type": "tx", "tx": {}},
    )
    rejected(
        "null tx inputs rejected",
        session,
        {"type": "tx", "tx": {"inputs": None, "outputs": []}},
    )
    rejected(
        "null tx outputs rejected",
        session,
        {"type": "tx", "tx": {"inputs": [], "outputs": None}},
    )
    rejected(
        "object tx inputs rejected",
        session,
        {"type": "tx", "tx": {"inputs": {}, "outputs": []}},
    )
    rejected(
        "object tx outputs rejected",
        session,
        {"type": "tx", "tx": {"inputs": [], "outputs": {}}},
    )

    reply = session.handle(
        {"type": "tx", "tx": {"inputs": [], "outputs": []}}
    )
    assert reply == {"type": "accepted", "kind": "tx", "id": "sec085"}
    assert mempool.last_tx is not None
    checks.append("explicit empty tx vectors preserved")
    print("[GREEN] explicit empty tx vectors preserved")

    print(f"SEC-085 explicit P2P tx vectors: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
