#!/usr/bin/env python3
"""SEC-115 bounds pre-handshake P2P frames independently of block-sync frames."""

import socket
import struct
import threading
import time

import axven
import p2p


class PrefixOnlySocket:
    def __init__(self, advertised_length):
        self._prefix = bytearray(struct.pack(">I", advertised_length))
        self.body_read = False
        self._timeout = None

    def recv(self, count):
        if self._prefix:
            chunk = bytes(self._prefix[:count])
            del self._prefix[:count]
            return chunk
        self.body_read = True
        raise AssertionError("oversized handshake attempted to read frame body")

    def gettimeout(self):
        return self._timeout

    def settimeout(self, value):
        self._timeout = value


def wait_until(fn, timeout=1.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if fn():
            return True
        time.sleep(0.02)
    return fn()


def client_count(server):
    with server._lock:
        return len(server._clients)


def main():
    checks = []

    def ok(name, condition):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    hello_bytes = p2p._json_bytes(p2p.hello_message())
    ok(
        "handshake byte budget is small and canonical hello fits",
        len(hello_bytes) < p2p.MAX_HANDSHAKE_MESSAGE_BYTES
        == 4 * 1024
        < p2p.MAX_MESSAGE_BYTES,
    )

    prefix_only = PrefixOnlySocket(p2p.MAX_HANDSHAKE_MESSAGE_BYTES + 1)
    try:
        p2p.recv_message(
            prefix_only,
            max_bytes=p2p.MAX_HANDSHAKE_MESSAGE_BYTES,
        )
    except p2p.ProtocolError:
        pass
    else:
        raise AssertionError("oversized handshake frame accepted")
    ok(
        "oversized handshake rejected before body read",
        not prefix_only.body_read,
    )

    left, right = socket.socketpair()
    try:
        payload = {
            "type": "padding",
            "padding": "x" * (p2p.MAX_HANDSHAKE_MESSAGE_BYTES + 512),
        }
        raw_size = len(p2p._json_bytes(payload))
        assert p2p.MAX_HANDSHAKE_MESSAGE_BYTES < raw_size < p2p.MAX_MESSAGE_BYTES
        p2p.send_message(right, payload)
        received = p2p.recv_message(left)
        ok(
            "post-handshake general frame budget remains available",
            received == payload,
        )
    finally:
        left.close()
        right.close()

    client, peer = socket.socketpair()
    responder_errors = []

    def oversized_responder():
        try:
            received = p2p.recv_message(peer)
            p2p.validate_handshake(received)
            peer.sendall(
                struct.pack(">I", p2p.MAX_HANDSHAKE_MESSAGE_BYTES + 1)
            )
        except Exception as exc:
            responder_errors.append(exc)
        finally:
            peer.close()

    thread = threading.Thread(target=oversized_responder, daemon=True)
    thread.start()
    try:
        try:
            p2p.handshake(client, deadline=time.monotonic() + 1.0)
        except p2p.ProtocolError:
            pass
        else:
            raise AssertionError("outbound handshake accepted oversized peer hello")
    finally:
        client.close()
        thread.join(1.0)
    ok(
        "outbound handshake enforces pre-auth frame budget",
        not responder_errors and not thread.is_alive(),
    )

    chain = axven.Blockchain()
    mempool = axven.Mempool(chain)
    server = p2p.NodeServer(chain, mempool).start()
    attacker = None
    try:
        attacker = socket.create_connection(server.address, timeout=1)
        attacker.settimeout(1)
        server_hello = p2p.recv_message(attacker)
        p2p.validate_handshake(server_hello)
        ok(
            "oversized pre-handshake peer registered",
            wait_until(lambda: client_count(server) == 1),
        )
        attacker.sendall(
            struct.pack(">I", p2p.MAX_HANDSHAKE_MESSAGE_BYTES + 1)
        )
        ok(
            "inbound oversized handshake is disconnected",
            wait_until(lambda: client_count(server) == 0),
        )
        attacker.close()
        attacker = None

        healthy = p2p.connect(server.address, timeout=1)
        try:
            status = p2p.request(healthy, {"type": "get_status"})
            ok(
                "listener survives oversized pre-auth frame",
                status["tip_hash"] == chain.tip.hash(),
            )
        finally:
            healthy.close()
    finally:
        if attacker is not None:
            try:
                attacker.close()
            except OSError:
                pass
        server.stop()

    source = open(p2p.__file__, "r", encoding="utf-8").read()
    ok(
        "handshake receive is explicitly wired to small frame cap",
        "max_bytes=MAX_HANDSHAKE_MESSAGE_BYTES" in source,
    )

    assert len(checks) == 8
    print("SEC-115 P2P handshake frame budget: 8/8 GREEN")


if __name__ == "__main__":
    main()
