#!/usr/bin/env python3
"""SEC-062 P2P canonical miner boundary contract."""

import axven
import p2p


def make_session():
    chain = axven.Blockchain()
    return chain, p2p.PeerSession(chain)


def raw_block(miner, height=1, nonce=0):
    return {
        "height": height,
        "timestamp": 1,
        "previous_hash": "f" * 64,
        "merkle_root": "a" * 64,
        "target": axven.MAX_TARGET,
        "transactions": [],
        "nonce": nonce,
        "miner": miner,
        "utxo_state_root": "0" * 64,
    }


def expect_protocol_error(fn, label):
    try:
        fn()
    except p2p.ProtocolError:
        print(f"[GREEN] {label}")
        return
    except Exception as exc:
        raise AssertionError(
            f"{label}: malformed miner escaped as "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    raise AssertionError(label)


def main():
    checks = 0

    # Canonical non-genesis miner must remain transport-valid.
    canonical = "N" + ("a" * 40)

    chain, session = make_session()
    reply = session.handle(
        {
            "type": "block",
            "block": raw_block(canonical),
        }
    )
    assert reply["type"] == "accepted"
    assert reply["status"] == "orphan"
    checks += 1
    print("[GREEN] canonical single-block miner preserved")

    # Exact canonical genesis must remain transport-compatible.
    chain, session = make_session()
    reply = session.handle(
        {
            "type": "block",
            "block": axven._genesis().to_dict(),
        }
    )
    assert reply["type"] == "accepted"
    assert reply["status"] == "duplicate"
    checks += 1
    print("[GREEN] canonical genesis miner preserved")

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "block",
                "block": raw_block({}),
            }
        ),
        "dictionary single-block miner rejected",
    )
    checks += 1

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "block",
                "block": raw_block([]),
            }
        ),
        "list single-block miner rejected",
    )
    checks += 1

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "block",
                "block": raw_block("N" + ("a" * 41)),
            }
        ),
        "oversized single-block miner rejected",
    )
    checks += 1

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "block",
                "block": raw_block("N" + ("g" * 40)),
            }
        ),
        "non-hex single-block miner rejected",
    )
    checks += 1

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "block",
                "block": raw_block("N" + ("a" * 999_999)),
            }
        ),
        "extreme single-block miner rejected",
    )
    checks += 1

    # Batch path must enforce exactly the same boundary.
    chain, session = make_session()
    reply = session.handle(
        {
            "type": "blocks",
            "blocks": [
                raw_block(canonical, nonce=1),
            ],
        }
    )
    assert reply == {
        "type": "accepted",
        "kind": "blocks",
        "count": 0,
    }
    checks += 1
    print("[GREEN] canonical batch miner preserved")

    chain, session = make_session()
    reply = session.handle(
        {
            "type": "blocks",
            "blocks": [
                axven._genesis().to_dict(),
            ],
        }
    )
    assert reply == {
        "type": "accepted",
        "kind": "blocks",
        "count": 1,
    }
    checks += 1
    print("[GREEN] canonical genesis batch miner preserved")

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "blocks",
                "blocks": [raw_block({}, nonce=2)],
            }
        ),
        "dictionary batch miner rejected",
    )
    checks += 1

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "blocks",
                "blocks": [raw_block([], nonce=3)],
            }
        ),
        "list batch miner rejected",
    )
    checks += 1

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "blocks",
                "blocks": [
                    raw_block("N" + ("a" * 41), nonce=4),
                ],
            }
        ),
        "oversized batch miner rejected",
    )
    checks += 1

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "blocks",
                "blocks": [
                    raw_block("N" + ("g" * 40), nonce=5),
                ],
            }
        ),
        "non-hex batch miner rejected",
    )
    checks += 1

    expect_protocol_error(
        lambda: make_session()[1].handle(
            {
                "type": "blocks",
                "blocks": [
                    raw_block("N" + ("a" * 999_999), nonce=6),
                ],
            }
        ),
        "extreme batch miner rejected",
    )
    checks += 1

    print(f"SEC-062 P2P canonical miner boundary: {checks}/14 GREEN")


if __name__ == "__main__":
    main()