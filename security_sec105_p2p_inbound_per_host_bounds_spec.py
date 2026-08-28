#!/usr/bin/env python3
"""SEC-105 per-source inbound P2P connection quota contract."""

import socket
import time

import p2p


ATTEMPTED_LOCAL_CONNECTIONS = 12


def snapshot(server):
    with server._lock:
        return len(server._clients), dict(server._client_hosts)


def wait_until(predicate, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def main():
    assert p2p.MAX_INBOUND_PEERS == 32
    assert p2p.MAX_INBOUND_PEERS_PER_HOST == 4
    print("[GREEN] global and per-host inbound quotas pinned")

    server = p2p.NodeServer().start()
    clients = []
    try:
        for _ in range(ATTEMPTED_LOCAL_CONNECTIONS):
            try:
                client = socket.create_connection(server.address, timeout=1.0)
                client.settimeout(1.0)
                clients.append(client)
            except OSError:
                pass

        assert wait_until(
            lambda: snapshot(server)[0] >= p2p.MAX_INBOUND_PEERS_PER_HOST,
            timeout=2.0,
        ), "server did not retain expected local peer quota"

        count, hosts = snapshot(server)
        local_host = server.address[0]
        local_count = sum(1 for host in hosts.values() if host == local_host)

        assert count <= p2p.MAX_INBOUND_PEERS, (
            f"global inbound quota exceeded: {count}"
        )
        assert local_count <= p2p.MAX_INBOUND_PEERS_PER_HOST, (
            f"single source retained {local_count} inbound slots"
        )
        assert count == len(hosts), "client/source accounting diverged"
        print(
            f"[GREEN] one source bounded at "
            f"{local_count}/{p2p.MAX_INBOUND_PEERS_PER_HOST} slots"
        )

        assert server._thread is not None and server._thread.is_alive()
        print("[GREEN] listener survives per-host quota saturation")

        for client in clients:
            try:
                client.close()
            except OSError:
                pass
        clients.clear()

        assert wait_until(lambda: snapshot(server)[0] == 0, timeout=2.0), (
            "closed clients did not release per-host slots"
        )
        print("[GREEN] closed clients release per-host quota accounting")

        fresh = socket.create_connection(server.address, timeout=1.0)
        fresh.settimeout(1.0)
        clients.append(fresh)
        assert wait_until(lambda: snapshot(server)[0] == 1, timeout=1.0)
        print("[GREEN] released source slot is reusable")

        print("SEC-105 inbound P2P per-host quota: 5/5 GREEN")
    finally:
        for client in clients:
            try:
                client.close()
            except OSError:
                pass
        server.stop()


if __name__ == "__main__":
    main()
