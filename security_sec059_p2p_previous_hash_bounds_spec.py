#!/usr/bin/env python3
"""SEC-059 P2P previous_hash length boundary regression contract."""

import axven
import p2p


MAX_HASH_CHARS = 64


def make_session():
    chain = axven.Blockchain()
    return chain, p2p.PeerSession(chain)


def raw_block(previous_hash, nonce=0):
    return {
        "height": 1,
        "timestamp": 1,
        "previous_hash": previous_hash,
        "merkle_root": "0" * 64,
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
            f"{label}: malformed previous_hash escaped as "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    raise AssertionError(label)


def main():
    checks = 0

    chain, session = make_session()
    reply = session.handle(
        {
            "type": "block",
            "block": raw_block("f" * MAX_HASH_CHARS),
        }
    )
    assert reply["type"] == "accepted"
    assert reply["status"] == "orphan"
    checks += 1
    print("[GREEN] canonical single-block previous_hash preserved")

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "block",
                "block": raw_block("f" * (MAX_HASH_CHARS + 1)),
            }
        ),
        "oversized single-block previous_hash rejected",
    )
    checks += 1

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "block",
                "block": raw_block("f" * 1_000_000),
            }
        ),
        "extreme single-block previous_hash rejected",
    )
    checks += 1

    chain, session = make_session()
    reply = session.handle(
        {
            "type": "blocks",
            "blocks": [raw_block("e" * MAX_HASH_CHARS, nonce=1)],
        }
    )
    assert reply == {
        "type": "accepted",
        "kind": "blocks",
        "count": 0,
    }
    checks += 1
    print("[GREEN] canonical batch previous_hash preserved")

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "blocks",
                "blocks": [
                    raw_block("e" * (MAX_HASH_CHARS + 1), nonce=2)
                ],
            }
        ),
        "oversized batch previous_hash rejected",
    )
    checks += 1

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "blocks",
                "blocks": [
                    raw_block("e" * 1_000_000, nonce=3)
                ],
            }
        ),
        "extreme batch previous_hash rejected",
    )
    checks += 1

    print(f"SEC-059 P2P previous_hash bounds: {checks}/6 GREEN")


if __name__ == "__main__":
    main()