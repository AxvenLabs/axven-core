#!/usr/bin/env python3
"""SEC-022 P2P transaction element structural validation contract."""

import axven
import p2p


def main():
    checks = []

    def rejected(name, session, msg):
        try:
            session.handle(msg)
        except p2p.ProtocolError:
            checks.append(name)
            print(f"[GREEN] {name}")
            return
        except (TypeError, ValueError, KeyError, AttributeError) as exc:
            raise AssertionError(
                f"{name}: malformed transaction element escaped as "
                f"{type(exc).__name__}"
            ) from exc
        raise AssertionError(name)

    chain = axven.Blockchain()
    mempool = axven.Mempool(chain)
    session = p2p.PeerSession(chain, mempool)

    rejected(
        "non-object tx input element rejected",
        session,
        {
            "type": "tx",
            "tx": {
                "inputs": [[]],
                "outputs": [],
            },
        },
    )

    rejected(
        "scalar tx input element rejected",
        session,
        {
            "type": "tx",
            "tx": {
                "inputs": [123],
                "outputs": [],
            },
        },
    )

    rejected(
        "non-object tx output element rejected",
        session,
        {
            "type": "tx",
            "tx": {
                "inputs": [],
                "outputs": [[]],
            },
        },
    )

    rejected(
        "scalar tx output element rejected",
        session,
        {
            "type": "tx",
            "tx": {
                "inputs": [],
                "outputs": [123],
            },
        },
    )

    print(
        f"SEC-022 P2P transaction element validation: "
        f"{len(checks)}/{len(checks)} GREEN"
    )


if __name__ == "__main__":
    main()
