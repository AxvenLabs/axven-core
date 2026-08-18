#!/usr/bin/env python3
"""SEC-018 bounded P2P transaction structure regression contract."""

import axven
import p2p


MAX_P2P_TX_INPUTS = 1024
MAX_P2P_TX_OUTPUTS = 1024


def main():
    checks = []

    def rejected(name, session, msg):
        try:
            session.handle(msg)
        except p2p.ProtocolError:
            checks.append(name)
            print(f"[GREEN] {name}")
            return
        except (TypeError, ValueError, KeyError):
            raise AssertionError(
                f"{name}: malformed P2P structure escaped as non-ProtocolError"
            )
        raise AssertionError(name)

    chain = axven.Blockchain()
    mempool = axven.Mempool(chain)
    session = p2p.PeerSession(chain, mempool)

    rejected(
        "non-object tx payload rejected",
        session,
        {
            "type": "tx",
            "tx": [],
        },
    )

    rejected(
        "non-list tx inputs rejected",
        session,
        {
            "type": "tx",
            "tx": {
                "inputs": {},
                "outputs": [],
            },
        },
    )

    rejected(
        "non-list tx outputs rejected",
        session,
        {
            "type": "tx",
            "tx": {
                "inputs": [],
                "outputs": {},
            },
        },
    )

    rejected(
        "oversized tx input list rejected",
        session,
        {
            "type": "tx",
            "tx": {
                "inputs": [{}] * (MAX_P2P_TX_INPUTS + 1),
                "outputs": [],
            },
        },
    )

    rejected(
        "oversized tx output list rejected",
        session,
        {
            "type": "tx",
            "tx": {
                "inputs": [],
                "outputs": [{}] * (MAX_P2P_TX_OUTPUTS + 1),
            },
        },
    )

    print(
        f"SEC-018 bounded P2P transaction structure: "
        f"{len(checks)}/{len(checks)} GREEN"
    )


if __name__ == "__main__":
    main()
