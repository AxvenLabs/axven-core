#!/usr/bin/env python3
"""SEC-060 P2P merkle_root length boundary regression contract."""

import axven
import p2p


MAX_ROOT_CHARS = 64


def make_session():
    chain = axven.Blockchain()
    return chain, p2p.PeerSession(chain)


def raw_block(merkle_root, nonce=0):
    return {
        "height": 1,
        "timestamp": 1,
        "previous_hash": "f" * 64,
        "merkle_root": merkle_root,
        "target": axven.MAX_TARGET,
        "transactions": [],
        "nonce": nonce,
        "miner": "",
        "utxo_state_root": "0" * 64,
    }


def expect_protocol_error(fn, label):
    try:
        fn()
    except p2p.ProtocolError:
        print(f"[GREEN] {label}")
        return
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        raise AssertionError(
            f"{label}: malformed merkle_root escaped as "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    raise AssertionError(label)


def main():
    checks = 0

    chain, session = make_session()
    reply = session.handle(
        {
            "type": "block",
            "block": raw_block("a" * MAX_ROOT_CHARS),
        }
    )
    assert reply["type"] == "accepted"
    assert reply["status"] == "orphan"
    checks += 1
    print("[GREEN] canonical single-block merkle_root preserved")

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "block",
                "block": raw_block("a" * (MAX_ROOT_CHARS + 1)),
            }
        ),
        "oversized single-block merkle_root rejected",
    )
    checks += 1

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "block",
                "block": raw_block("a" * 1_000_000),
            }
        ),
        "extreme single-block merkle_root rejected",
    )
    checks += 1

    chain, session = make_session()
    reply = session.handle(
        {
            "type": "blocks",
            "blocks": [raw_block("b" * MAX_ROOT_CHARS, nonce=1)],
        }
    )
    assert reply == {
        "type": "accepted",
        "kind": "blocks",
        "count": 0,
    }
    checks += 1
    print("[GREEN] canonical batch merkle_root preserved")

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "blocks",
                "blocks": [
                    raw_block("b" * (MAX_ROOT_CHARS + 1), nonce=2)
                ],
            }
        ),
        "oversized batch merkle_root rejected",
    )
    checks += 1

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "blocks",
                "blocks": [
                    raw_block("b" * 1_000_000, nonce=3)
                ],
            }
        ),
        "extreme batch merkle_root rejected",
    )
    checks += 1

    print(f"SEC-060 P2P merkle_root bounds: {checks}/6 GREEN")


if __name__ == "__main__":
    main()