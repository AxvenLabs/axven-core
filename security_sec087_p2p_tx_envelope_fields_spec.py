#!/usr/bin/env python3
"""SEC-087 requires canonical fields on inbound P2P tx envelopes."""

import axven
import p2p


class _RecordingMempool:
    def __init__(self):
        self.last_tx = None

    def add(self, tx):
        self.last_tx = tx
        return "sec087"


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
    tx = {"inputs": [], "outputs": []}

    rejected(
        "unknown scalar tx envelope field rejected",
        session,
        {"type": "tx", "tx": tx, "extra": 1},
    )
    rejected(
        "unknown null tx envelope field rejected",
        session,
        {"type": "tx", "tx": tx, "extra": None},
    )
    rejected(
        "unknown empty object tx envelope field rejected",
        session,
        {"type": "tx", "tx": tx, "extra": {}},
    )
    rejected(
        "unknown empty list tx envelope field rejected",
        session,
        {"type": "tx", "tx": tx, "extra": []},
    )
    rejected(
        "multiple unknown tx envelope fields rejected",
        session,
        {"type": "tx", "tx": tx, "extra": 0, "other": ""},
    )

    reply = session.handle({"type": "tx", "tx": tx})
    assert reply == {"type": "accepted", "kind": "tx", "id": "sec087"}
    assert mempool.last_tx is not None
    checks.append("canonical tx envelope preserved")
    print("[GREEN] canonical tx envelope preserved")

    print(f"SEC-087 canonical P2P tx envelope: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
