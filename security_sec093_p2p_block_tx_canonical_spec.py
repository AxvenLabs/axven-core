#!/usr/bin/env python3
"""SEC-093 canonical nested transaction validation for P2P block messages."""

import copy

import axven
import p2p
from p2p_tx_bounds import MAX_P2P_TX_AUTH_CHARS


def _canonical_block():
    source = axven.Blockchain()
    miner = axven.Wallet()
    return source.build_candidate(miner.address).to_dict()


def _rejected(name, message):
    session = p2p.PeerSession(axven.Blockchain())
    try:
        session.handle(message)
    except p2p.ProtocolError:
        print(f"[GREEN] {name}")
        return
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        raise AssertionError(
            f"{name}: malformed nested transaction escaped as "
            f"{type(exc).__name__}"
        ) from exc
    raise AssertionError(name)


def main():
    checks = 0

    raw = _canonical_block()
    raw["transactions"][0] = []
    _rejected(
        "non-object nested transaction rejected",
        {"type": "block", "block": raw},
    )
    checks += 1

    raw = _canonical_block()
    raw["transactions"][0].pop("inputs")
    _rejected(
        "nested transaction missing inputs rejected",
        {"type": "block", "block": raw},
    )
    checks += 1

    raw = _canonical_block()
    raw["transactions"][0]["unexpected"] = True
    _rejected(
        "nested transaction unknown top-level field rejected",
        {"type": "block", "block": raw},
    )
    checks += 1

    raw = _canonical_block()
    raw["transactions"][0]["inputs"][0]["prev_txid"] = 0
    _rejected(
        "nested transaction string types enforced",
        {"type": "block", "block": raw},
    )
    checks += 1

    raw = _canonical_block()
    raw["transactions"][0]["outputs"][0]["amount"] = "1"
    _rejected(
        "nested transaction numeric types enforced",
        {"type": "block", "block": raw},
    )
    checks += 1

    raw = _canonical_block()
    raw["transactions"][0]["inputs"][0]["signature"] = (
        "A" * (MAX_P2P_TX_AUTH_CHARS + 1)
    )
    _rejected(
        "nested transaction auth budget enforced",
        {"type": "block", "block": raw},
    )
    checks += 1

    raw = _canonical_block()
    raw["transactions"][0]["unexpected"] = True
    _rejected(
        "block-batch nested transaction canonicality enforced",
        {"type": "blocks", "blocks": [raw]},
    )
    checks += 1

    session = p2p.PeerSession(axven.Blockchain())
    raw = _canonical_block()
    reply = session.handle({"type": "block", "block": copy.deepcopy(raw)})
    assert reply["type"] == "accepted"
    assert reply["kind"] == "block"
    assert reply["status"] == "extended"
    checks += 1
    print("[GREEN] canonical healthy block preserved")

    print(f"SEC-093 P2P nested tx canonicality: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
