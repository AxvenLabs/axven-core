#!/usr/bin/env python3
"""SEC-098 canonical P2P hello-field regression contract."""

import socket
import threading
import time

import p2p


def expect_rejected(msg):
    try:
        p2p.validate_handshake(msg)
    except p2p.ProtocolError:
        return
    raise AssertionError("hello message with unknown field was accepted")


def main():
    canonical = p2p.hello_message()
    p2p.validate_handshake(dict(canonical))
    print("[GREEN] canonical hello accepted")

    for value in (None, True, 1, "x", [], {}, {"nested": [1, 2, 3]}):
        bad = dict(canonical)
        bad["extension"] = value
        expect_rejected(bad)
    print("[GREEN] unknown hello fields rejected")

    client, peer = socket.socketpair()
    errors = []

    def responder():
        try:
            received = p2p.recv_message(peer)
            assert received == p2p.hello_message()
            bad = p2p.hello_message()
            bad["extension"] = {"ignored": True}
            p2p.send_message(peer, bad)
        except Exception as exc:
            errors.append(exc)
        finally:
            peer.close()

    thread = threading.Thread(target=responder, daemon=True)
    thread.start()
    try:
        try:
            p2p.handshake(client, deadline=time.monotonic() + 2.0)
        except p2p.ProtocolError:
            pass
        else:
            raise AssertionError("wire handshake accepted unknown hello field")
    finally:
        client.close()
        thread.join(2.0)

    assert not errors, errors
    print("[GREEN] wire handshake enforces canonical hello fields")
    print("SEC-098 canonical P2P hello fields: 3/3 GREEN")


if __name__ == "__main__":
    main()
