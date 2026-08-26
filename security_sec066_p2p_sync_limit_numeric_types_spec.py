#!/usr/bin/env python3
"""SEC-066 canonical P2P get_blocks limit type contract."""

import axven
import p2p


class TrapChain:
    @property
    def _state_lock(self):
        raise AssertionError("invalid sync limit reached chain-state read")


def expect_rejected(session, value):
    try:
        session.handle(
            {
                "type": "get_blocks",
                "locator": [],
                "limit": value,
            }
        )
    except p2p.ProtocolError as exc:
        assert str(exc) == "invalid block limit", (
            f"unexpected P2P rejection: {exc}"
        )
        return
    raise AssertionError(f"non-integer sync limit accepted: {value!r}")


def main():
    checks = 0
    trap_session = p2p.PeerSession(TrapChain())

    invalid_values = (
        ("numeric string", "1"),
        ("float", 1.0),
        ("boolean", True),
        ("null", None),
    )

    for label, value in invalid_values:
        expect_rejected(trap_session, value)
        checks += 1
        print(f"[GREEN] {label} get_blocks limit rejected before chain read")

    chain = axven.Blockchain()
    session = p2p.PeerSession(chain)
    locator = [chain.blocks[0].hash()]

    reply = session.handle(
        {
            "type": "get_blocks",
            "locator": locator,
            "limit": p2p.MAX_SYNC_BLOCKS,
        }
    )
    assert reply == {"type": "blocks", "blocks": []}
    checks += 1
    print("[GREEN] maximum canonical integer sync limit accepted")

    reply = session.handle(
        {
            "type": "get_blocks",
            "locator": locator,
        }
    )
    assert reply == {"type": "blocks", "blocks": []}
    checks += 1
    print("[GREEN] omitted sync limit preserves canonical default")

    print(f"SEC-066 P2P sync limit numeric types: {checks}/6 GREEN")


if __name__ == "__main__":
    main()
