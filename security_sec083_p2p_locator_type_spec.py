#!/usr/bin/env python3
# SEC-083 canonical P2P get_blocks locator structure contract.

import axven
import p2p


def expect_rejected(session, locator, label):
    try:
        session.handle({"type": "get_blocks", "locator": locator, "limit": 1})
    except p2p.ProtocolError:
        print(f"[GREEN] {label}")
        return
    raise AssertionError(label)


def main():
    chain = axven.Blockchain()
    session = p2p.PeerSession(chain)

    reply = session.handle({"type": "get_blocks", "limit": 1})
    assert reply["type"] == "blocks" and len(reply["blocks"]) == 1
    print("[GREEN] omitted locator preserves empty-list default")

    reply = session.handle({"type": "get_blocks", "locator": [], "limit": 1})
    assert reply["type"] == "blocks" and len(reply["blocks"]) == 1
    print("[GREEN] explicit empty locator list preserved")

    reply = session.handle({"type": "get_blocks", "locator": session.locator(), "limit": 1})
    assert reply["type"] == "blocks"
    print("[GREEN] canonical locator list preserved")

    for bad, label in (
        (None, "null locator rejected"),
        (False, "boolean locator rejected"),
        (0, "numeric locator rejected"),
        ("", "string locator rejected"),
        ({}, "object locator rejected"),
    ):
        expect_rejected(session, bad, label)

    print("SEC-083 P2P get_blocks locator type: 8/8 GREEN")


if __name__ == "__main__":
    main()
