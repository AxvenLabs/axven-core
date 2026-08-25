#!/usr/bin/env python3
"""SEC-058 P2P locator hash length boundary regression contract."""

import axven
import p2p


MAX_LOCATOR_HASH_CHARS = 64


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
                f"{name}: oversized locator escaped as "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        raise AssertionError(name)

    chain = axven.Blockchain()
    session = p2p.PeerSession(chain)

    canonical = chain.blocks[0].hash()
    assert len(canonical) == MAX_LOCATOR_HASH_CHARS

    reply = session.handle(
        {
            "type": "get_blocks",
            "locator": [canonical],
            "limit": 1,
        }
    )
    assert reply["type"] == "blocks"
    checks.append("canonical locator hash accepted")
    print("[GREEN] canonical locator hash accepted")

    reply = session.handle(
        {
            "type": "get_blocks",
            "locator": ["f" * MAX_LOCATOR_HASH_CHARS],
            "limit": 1,
        }
    )
    assert reply["type"] == "blocks"
    checks.append("maximum locator hash length accepted")
    print("[GREEN] maximum locator hash length accepted")

    rejected(
        "oversized locator hash rejected",
        session,
        {
            "type": "get_blocks",
            "locator": ["f" * (MAX_LOCATOR_HASH_CHARS + 1)],
            "limit": 1,
        },
    )

    rejected(
        "extreme locator hash rejected",
        session,
        {
            "type": "get_blocks",
            "locator": ["f" * 1_000_000],
            "limit": 1,
        },
    )

    print(
        f"SEC-058 P2P locator hash bounds: "
        f"{len(checks)}/{len(checks)} GREEN"
    )


if __name__ == "__main__":
    main()