#!/usr/bin/env python3
"""SEC-015 inbound P2P stalled-peer timeout regression contract."""

import socket
import time

import axven
import p2p


TEST_TIMEOUT = 0.20
SETTLE_TIMEOUT = 1.00


def wait_until(fn, timeout=SETTLE_TIMEOUT):
    deadline = time.time() + timeout
    while time.time() < deadline:
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

    # The production server will use this value after SEC-015 is implemented.
    # Current pre-fix code ignores it, which must keep this contract RED.
    p2p.INBOUND_PEER_TIMEOUT = TEST_TIMEOUT

    chain = axven.Blockchain()
    mempool = axven.Mempool(chain)
    server = p2p.NodeServer(chain, mempool).start()

    silent = None
    partial = None

    try:
        # Case 1: TCP connection established, but peer sends no handshake bytes.
        silent = socket.create_connection(server.address, timeout=1)
        ok(
            "silent peer registered",
            wait_until(lambda: client_count(server) == 1),
        )

        ok(
            "silent pre-handshake peer timed out",
            wait_until(lambda: client_count(server) == 0),
        )

        silent.close()
        silent = None

        # Case 2: Peer advertises a legal frame length but stalls mid-frame.
        partial = socket.create_connection(server.address, timeout=1)

        frame_length = 128
        partial.sendall(frame_length.to_bytes(4, "big"))
        partial.sendall(b'{"type":')

        ok(
            "partial-frame peer registered",
            wait_until(lambda: client_count(server) == 1),
        )

        ok(
            "partial-frame peer timed out",
            wait_until(lambda: client_count(server) == 0),
        )

        partial.close()
        partial = None

        # Timeout handling must not poison the listener.
        healthy = p2p.connect(server.address, timeout=1)
        try:
            status = p2p.request(healthy, {"type": "get_status"})
            ok(
                "listener survives stalled peers",
                status["tip_hash"] == chain.tip.hash(),
            )
        finally:
            healthy.close()

    finally:
        if silent is not None:
            try:
                silent.close()
            except OSError:
                pass

        if partial is not None:
            try:
                partial.close()
            except OSError:
                pass

        server.stop()

    print(f"SEC-015 inbound P2P timeout: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
