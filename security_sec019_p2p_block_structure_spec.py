#!/usr/bin/env python3
"""SEC-019 P2P single-block structural boundary regression contract."""

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
                f"{name}: malformed P2P block escaped as "
                f"{type(exc).__name__}"
            ) from exc
        raise AssertionError(name)

    chain = axven.Blockchain()
    session = p2p.PeerSession(chain)

    rejected(
        "non-object block payload rejected",
        session,
        {
            "type": "block",
            "block": [],
        },
    )

    rejected(
        "missing block payload rejected",
        session,
        {
            "type": "block",
        },
    )

    rejected(
        "non-list block transactions rejected",
        session,
        {
            "type": "block",
            "block": {
                "height": 1,
                "timestamp": 1,
                "previous_hash": chain.tip.hash(),
                "merkle_root": "00" * 32,
                "target": axven.MAX_TARGET,
                "transactions": {},
                "nonce": 0,
                "miner": "",
                "utxo_state_root": "",
            },
        },
    )

    print(
        f"SEC-019 P2P single-block structural boundary: "
        f"{len(checks)}/{len(checks)} GREEN"
    )


if __name__ == "__main__":
    main()
