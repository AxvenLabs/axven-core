#!/usr/bin/env python3
"""SEC-020 P2P locator element structural validation contract."""

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
                f"{name}: malformed locator escaped as {type(exc).__name__}"
            ) from exc
        raise AssertionError(name)

    chain = axven.Blockchain()
    session = p2p.PeerSession(chain)

    rejected(
        "dict locator element rejected",
        session,
        {
            "type": "get_blocks",
            "locator": [{}],
            "limit": 1,
        },
    )

    rejected(
        "list locator element rejected",
        session,
        {
            "type": "get_blocks",
            "locator": [[]],
            "limit": 1,
        },
    )

    rejected(
        "non-string locator element rejected",
        session,
        {
            "type": "get_blocks",
            "locator": [123],
            "limit": 1,
        },
    )

    reply = session.handle(
        {
            "type": "get_blocks",
            "locator": [chain.blocks[0].hash()],
            "limit": 1,
        }
    )

    assert reply["type"] == "blocks"
    checks.append("valid locator element accepted")
    print("[GREEN] valid locator element accepted")

    print(
        f"SEC-020 P2P locator element validation: "
        f"{len(checks)}/{len(checks)} GREEN"
    )


if __name__ == "__main__":
    main()
