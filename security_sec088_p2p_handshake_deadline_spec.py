#!/usr/bin/env python3
"""SEC-088 enforces an absolute inbound P2P handshake deadline."""

import socket
import time

import axven
import p2p


TEST_HANDSHAKE_DEADLINE = 0.30
TEST_IO_TIMEOUT = 1.00
SETTLE_TIMEOUT = 1.20


def wait_until(fn, timeout=SETTLE_TIMEOUT):
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

    p2p.INBOUND_PEER_TIMEOUT = TEST_IO_TIMEOUT
    p2p.INBOUND_HANDSHAKE_TIMEOUT = TEST_HANDSHAKE_DEADLINE

    chain = axven.Blockchain()
    mempool = axven.Mempool(chain)
    server = p2p.NodeServer(chain, mempool).start()
    slow = None

    try:
        slow = socket.create_connection(server.address, timeout=1)
        ok("slow peer registered", wait_until(lambda: client_count(server) == 1))

        # Advertise a legal frame and keep sending bytes faster than the normal
        # per-recv timeout.  A per-operation timeout alone would never fire.
        slow.sendall((512).to_bytes(4, "big"))
        started = time.monotonic()
        for _ in range(12):
            try:
                slow.sendall(b"{")
            except OSError:
                break
            time.sleep(0.05)

        ok(
            "trickle handshake dropped by absolute deadline",
            wait_until(lambda: client_count(server) == 0, timeout=0.80),
        )
        ok(
            "absolute deadline beats normal io timeout",
            time.monotonic() - started < TEST_IO_TIMEOUT,
        )

        try:
            slow.close()
        except OSError:
            pass
        slow = None

        healthy = p2p.connect(server.address, timeout=1)
        try:
            status = p2p.request(healthy, {"type": "get_status"})
            ok("listener survives slowloris peer", status["tip_hash"] == chain.tip.hash())
        finally:
            healthy.close()

    finally:
        if slow is not None:
            try:
                slow.close()
            except OSError:
                pass
        server.stop()

    print(f"SEC-088 absolute P2P handshake deadline: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
