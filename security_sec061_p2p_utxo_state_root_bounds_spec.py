#!/usr/bin/env python3
"""SEC-061 P2P utxo_state_root boundary regression contract."""

import axven
import p2p


MAX_ROOT_CHARS = 64


def make_session():
    chain = axven.Blockchain()
    return chain, p2p.PeerSession(chain)


def raw_block(utxo_state_root, nonce=0):
    return {
        "height": 1,
        "timestamp": 1,
        "previous_hash": "f" * 64,
        "merkle_root": "a" * 64,
        "target": axven.MAX_TARGET,
        "transactions": [],
        "nonce": nonce,
        "miner": "N" + ("a" * 40),
        "utxo_state_root": utxo_state_root,
    }


def expect_protocol_error(fn, label):
    try:
        fn()
    except p2p.ProtocolError:
        print(f"[GREEN] {label}")
        return
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        raise AssertionError(
            f"{label}: malformed utxo_state_root escaped as "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    raise AssertionError(label)


def main():
    checks = 0

    chain, session = make_session()
    reply = session.handle(
        {
            "type": "block",
            "block": raw_block("0" * MAX_ROOT_CHARS),
        }
    )
    assert reply["type"] == "accepted"
    assert reply["status"] == "orphan"
    checks += 1
    print("[GREEN] canonical single-block utxo_state_root preserved")

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "block",
                "block": raw_block({}),
            }
        ),
        "non-string single-block utxo_state_root rejected",
    )
    checks += 1

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "block",
                "block": raw_block("0" * (MAX_ROOT_CHARS + 1)),
            }
        ),
        "oversized single-block utxo_state_root rejected",
    )
    checks += 1

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "block",
                "block": raw_block("0" * 1_000_000),
            }
        ),
        "extreme single-block utxo_state_root rejected",
    )
    checks += 1

    chain, session = make_session()
    reply = session.handle(
        {
            "type": "blocks",
            "blocks": [
                raw_block("1" * MAX_ROOT_CHARS, nonce=1)
            ],
        }
    )
    assert reply == {
        "type": "accepted",
        "kind": "blocks",
        "count": 0,
    }
    checks += 1
    print("[GREEN] canonical batch utxo_state_root preserved")

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "blocks",
                "blocks": [raw_block({}, nonce=2)],
            }
        ),
        "non-string batch utxo_state_root rejected",
    )
    checks += 1

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "blocks",
                "blocks": [
                    raw_block("1" * (MAX_ROOT_CHARS + 1), nonce=3)
                ],
            }
        ),
        "oversized batch utxo_state_root rejected",
    )
    checks += 1

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "blocks",
                "blocks": [
                    raw_block("1" * 1_000_000, nonce=4)
                ],
            }
        ),
        "extreme batch utxo_state_root rejected",
    )
    checks += 1

    print(f"SEC-061 P2P utxo_state_root bounds: {checks}/8 GREEN")


if __name__ == "__main__":
    main()