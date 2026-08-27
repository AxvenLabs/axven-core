#!/usr/bin/env python3
"""SEC-088 bounds total inbound P2P frame receive time against slowloris peers."""

import socket
import threading
import time

import axven
import p2p

TEST_HANDSHAKE_DEADLINE = 0.25
TEST_MESSAGE_DEADLINE = 0.30
TRICKLE_INTERVAL = 0.08
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


def trickle(sock, payload):
    try:
        sock.sendall(len(payload).to_bytes(4, "big"))
        for byte in payload:
            sock.sendall(bytes((byte,)))
            time.sleep(TRICKLE_INTERVAL)
    except OSError:
        pass


def main():
    checks = []

    def ok(name, condition):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    p2p.INBOUND_PEER_TIMEOUT = TEST_HANDSHAKE_DEADLINE
    p2p.INBOUND_MESSAGE_DEADLINE = TEST_MESSAGE_DEADLINE

    left, right = socket.socketpair()
    try:
        left.settimeout(0.05)
        started = time.monotonic()
        try:
            p2p._recv_exact(
                left,
                1,
                deadline=time.monotonic() + 0.30,
            )
        except p2p.ProtocolError:
            elapsed = time.monotonic() - started
        else:
            raise AssertionError("shorter socket timeout was relaxed")
        ok(
            "absolute deadline preserves shorter socket timeout",
            elapsed < 0.20,
        )
    finally:
        left.close()
        right.close()

    chain = axven.Blockchain()
    mempool = axven.Mempool(chain)
    server = p2p.NodeServer(chain, mempool).start()
    pre = None
    post = None

    try:
        pre = socket.create_connection(server.address, timeout=1)
        ok("pre-handshake trickle peer registered", wait_until(lambda: client_count(server) == 1))
        hello = p2p._json_bytes(p2p.hello_message())
        threading.Thread(target=trickle, args=(pre, hello), daemon=True).start()
        ok(
            "pre-handshake trickle peer hit absolute deadline",
            wait_until(lambda: client_count(server) == 0),
        )
        pre.close()
        pre = None

        post = socket.create_connection(server.address, timeout=1)
        post.settimeout(1)
        p2p.handshake(post)
        ok("post-handshake trickle peer registered", wait_until(lambda: client_count(server) == 1))
        payload = p2p._json_bytes({"type": "get_status"})
        threading.Thread(target=trickle, args=(post, payload), daemon=True).start()
        ok(
            "post-handshake trickle frame hit absolute deadline",
            wait_until(lambda: client_count(server) == 0),
        )
        post.close()
        post = None

        healthy = p2p.connect(server.address, timeout=1)
        try:
            status = p2p.request(healthy, {"type": "get_status"})
            ok("listener survives slowloris peers", status["tip_hash"] == chain.tip.hash())
        finally:
            healthy.close()
    finally:
        for sock in (pre, post):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        server.stop()

    print(f"SEC-088 absolute P2P receive deadline: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
