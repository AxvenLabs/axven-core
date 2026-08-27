#!/usr/bin/env python3
"""SEC-086 rejects unknown top-level fields in P2P transaction payloads."""

import axven
import p2p


class _RecordingMempool:
    def __init__(self):
        self.last_tx = None

    def add(self, tx):
        self.last_tx = tx
        return "sec086"


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
        "unknown scalar tx field rejected",
        session,
        {"type": "tx", "tx": {"inputs": [], "outputs": [], "fee": 0}},
    )
    rejected(
        "unknown object tx field rejected",
        session,
        {"type": "tx", "tx": {"inputs": [], "outputs": [], "metadata": {}}},
    )
    rejected(
        "unknown empty-string tx field rejected",
        session,
        {"type": "tx", "tx": {"inputs": [], "outputs": [], "memo": ""}},
    )
    rejected(
        "multiple unknown tx fields rejected",
        session,
        {
            "type": "tx",
            "tx": {
                "inputs": [],
                "outputs": [],
                "fee": 0,
                "metadata": {},
            },
        },
    )

    reply = session.handle(
        {"type": "tx", "tx": {"inputs": [], "outputs": []}}
    )
    assert reply == {"type": "accepted", "kind": "tx", "id": "sec086"}
    checks.append("canonical tx fields preserved")
    print("[GREEN] canonical tx fields preserved")

    reply = session.handle(
        {
            "type": "tx",
            "tx": {
                "inputs": [],
                "outputs": [],
                "coinbase_height": 1,
            },
        }
    )
    assert reply == {"type": "accepted", "kind": "tx", "id": "sec086"}
    checks.append("known optional tx field preserved")
    print("[GREEN] known optional tx field preserved")

    print(f"SEC-086 canonical P2P tx fields: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
