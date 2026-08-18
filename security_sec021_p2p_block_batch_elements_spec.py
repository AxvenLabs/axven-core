#!/usr/bin/env python3
"""SEC-021 P2P block-batch element structural validation contract."""

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
                f"{name}: malformed block-batch element escaped as "
                f"{type(exc).__name__}"
            ) from exc
        raise AssertionError(name)

    chain = axven.Blockchain()
    session = p2p.PeerSession(chain)

    rejected(
        "non-object block batch element rejected",
        session,
        {
            "type": "blocks",
            "blocks": [[]],
        },
    )

    rejected(
        "scalar block batch element rejected",
        session,
        {
            "type": "blocks",
            "blocks": [123],
        },
    )

    rejected(
        "non-list transactions in batch block rejected",
        session,
        {
            "type": "blocks",
            "blocks": [
                {
                    "height": 1,
                    "timestamp": 1,
                    "previous_hash": chain.tip.hash(),
                    "merkle_root": "00" * 32,
                    "target": axven.MAX_TARGET,
                    "transactions": {},
                    "nonce": 0,
                    "miner": "",
                    "utxo_state_root": "",
                }
            ],
        },
    )

    reply = session.handle(
        {
            "type": "blocks",
            "blocks": [],
        }
    )

    assert reply == {
        "type": "accepted",
        "kind": "blocks",
        "count": 0,
    }
    checks.append("empty valid block batch accepted")
    print("[GREEN] empty valid block batch accepted")

    print(
        f"SEC-021 P2P block-batch element validation: "
        f"{len(checks)}/{len(checks)} GREEN"
    )


if __name__ == "__main__":
    main()
