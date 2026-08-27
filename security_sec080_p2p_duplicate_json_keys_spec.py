#!/usr/bin/env python3
"""SEC-080: P2P JSON objects must reject duplicate keys at every depth."""

import socket
import struct

import p2p


def recv_raw(raw: bytes):
    sender, receiver = socket.socketpair()
    try:
        sender.sendall(struct.pack(">I", len(raw)) + raw)
        return p2p.recv_message(receiver)
    finally:
        sender.close()
        receiver.close()


def expect_duplicate(raw: bytes, key: str):
    try:
        recv_raw(raw)
    except p2p.ProtocolError as exc:
        assert f"duplicate JSON key: {key}" in str(exc), str(exc)
        return
    raise AssertionError(f"duplicate JSON key accepted: {key}")


def main():
    canonical = recv_raw(
        b'{"type":"probe","nested":{"value":1},"items":[{"x":2}]}'
    )
    assert canonical == {
        "type": "probe",
        "nested": {"value": 1},
        "items": [{"x": 2}],
    }
    print("[GREEN] canonical unique-key P2P JSON preserved")

    expect_duplicate(
        b'{"type":"status","type":"get_status"}',
        "type",
    )
    print("[GREEN] duplicate top-level message type rejected")

    expect_duplicate(
        b'{"type":"hello","protocol_version":1,"protocol_version":2}',
        "protocol_version",
    )
    print("[GREEN] duplicate handshake identity field rejected")

    expect_duplicate(
        b'{"type":"tx","tx":{"inputs":[],"outputs":[{"recipient":"A","amount":1,"amount":2}]}}',
        "amount",
    )
    print("[GREEN] duplicate nested transaction field rejected")

    expect_duplicate(
        b'{"type":"blocks","blocks":[{"height":1,"height":2}]}',
        "height",
    )
    print("[GREEN] duplicate nested block field rejected")

    try:
        recv_raw(b'{"type":')
    except p2p.ProtocolError as exc:
        assert str(exc) == "invalid json", str(exc)
    else:
        raise AssertionError("malformed JSON accepted")
    print("[GREEN] malformed JSON still fails closed")

    try:
        recv_raw(b'["get_status"]')
    except p2p.ProtocolError as exc:
        assert str(exc) == "message must be object", str(exc)
    else:
        raise AssertionError("non-object P2P JSON accepted")
    print("[GREEN] non-object P2P JSON still rejected")

    print("SEC-080 P2P duplicate JSON keys: 7/7 GREEN")


if __name__ == "__main__":
    main()
