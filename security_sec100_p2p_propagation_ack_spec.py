#!/usr/bin/env python3
"""SEC-100 outbound P2P propagation acknowledgement contract."""

import p2p


def expect_rejected(reply, kind, expected_id):
    try:
        p2p._validate_propagation_ack(reply, kind, expected_id)
    except p2p.ProtocolError:
        return
    raise AssertionError(f"malformed {kind} propagation acknowledgement accepted: {reply!r}")


def main():
    txid = "11" * 32
    blockid = "22" * 32

    tx_ack = {"type": "accepted", "kind": "tx", "id": txid}
    assert p2p._validate_propagation_ack(dict(tx_ack), "tx", txid) == tx_ack
    print("[GREEN] canonical tx acknowledgement accepted")

    block_ack = {
        "type": "accepted",
        "kind": "block",
        "id": blockid,
        "status": "extended",
    }
    assert p2p._validate_propagation_ack(dict(block_ack), "block", blockid) == block_ack
    print("[GREEN] canonical block acknowledgement accepted")

    malformed_tx = [
        {"type": "status"},
        {"type": "accepted", "kind": "block", "id": txid},
        {"type": "accepted", "kind": "tx", "id": "00" * 32},
        {"type": "accepted", "kind": "tx", "id": txid, "extra": True},
        {"type": "accepted", "kind": "tx"},
    ]
    for reply in malformed_tx:
        expect_rejected(reply, "tx", txid)
    print("[GREEN] malformed tx acknowledgements rejected")

    malformed_block = [
        {"type": "accepted", "kind": "block", "id": blockid},
        {"type": "accepted", "kind": "block", "id": blockid, "status": "forged"},
        {"type": "accepted", "kind": "tx", "id": blockid, "status": "extended"},
        {"type": "accepted", "kind": "block", "id": "00" * 32, "status": "extended"},
        {"type": "accepted", "kind": "block", "id": blockid, "status": "extended", "extra": 1},
    ]
    for reply in malformed_block:
        expect_rejected(reply, "block", blockid)
    print("[GREEN] malformed block acknowledgements rejected")

    for status in ("extended", "reorg", "side-chain", "duplicate", "orphan"):
        reply = {"type": "accepted", "kind": "block", "id": blockid, "status": status}
        p2p._validate_propagation_ack(reply, "block", blockid)
    print("[GREEN] canonical block acknowledgement statuses preserved")
    print("SEC-100 P2P propagation acknowledgement: 5/5 GREEN")


if __name__ == "__main__":
    main()
