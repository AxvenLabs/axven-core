#!/usr/bin/env python3
"""SEC-028 bounded concurrent inbound P2P peer regression contract."""

import socket
import time

import p2p


EXPECTED_MAX_INBOUND_PEERS = 32
ATTEMPTED_PEERS = EXPECTED_MAX_INBOUND_PEERS + 16


def client_count(server):
    with server._lock:
        return len(server._clients)


def wait_until(predicate, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def main():
    server = p2p.NodeServer().start()
    clients = []

    try:
        for _ in range(ATTEMPTED_PEERS):
            try:
                s = socket.create_connection(server.address, timeout=1.0)
                s.settimeout(1.0)
                clients.append(s)
            except OSError:
                pass

        wait_until(
            lambda: client_count(server) >= min(
                len(clients),
                EXPECTED_MAX_INBOUND_PEERS,
            ),
            timeout=2.0,
        )

        count = client_count(server)

        assert count <= EXPECTED_MAX_INBOUND_PEERS, (
            f"inbound peer set unbounded: "
            f"{count} concurrent clients retained, "
            f"expected <= {EXPECTED_MAX_INBOUND_PEERS}"
        )

        print(
            f"[GREEN] inbound peers bounded at "
            f"{count}/{EXPECTED_MAX_INBOUND_PEERS}"
        )

        # Listener must remain alive after saturation.
        assert server._thread is not None
        assert server._thread.is_alive()

        print("[GREEN] listener survives inbound peer saturation")
        print("SEC-028 bounded concurrent inbound peers: 2/2 GREEN")

    finally:
        for s in clients:
            try:
                s.close()
            except OSError:
                pass
        server.stop()


if __name__ == "__main__":
    main()
