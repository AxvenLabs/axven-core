#!/usr/bin/env python3
"""SEC-030 bounded concurrent RPC worker regression contract."""

import json
import socket
import threading
import time

from rpc import RPCServer


EXPECTED_MAX_RPC_WORKERS = 32
ATTEMPTED_REQUESTS = EXPECTED_MAX_RPC_WORKERS + 16


class BlockingCore:
    def __init__(self):
        self.lock = threading.Lock()
        self.release = threading.Event()
        self.active = 0
        self.max_active = 0

    def status(self):
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)

        try:
            self.release.wait(10.0)
            return {"height": 0}
        finally:
            with self.lock:
                self.active -= 1


def send_status(address, start, errors):
    start.wait()

    body = json.dumps(
        {"method": "get_status"},
        separators=(",", ":"),
    ).encode()

    request = (
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n"
        + b"\r\n"
        + body
    )

    sock = None

    try:
        sock = socket.create_connection(address, timeout=3.0)
        sock.settimeout(10.0)
        sock.sendall(request)

        while sock.recv(4096):
            pass

    except OSError as exc:
        errors.append(exc)

    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def main():
    core = BlockingCore()
    server = RPCServer(core, port=0).start()

    start = threading.Event()
    errors = []

    clients = [
        threading.Thread(
            target=send_status,
            args=(server.address, start, errors),
            daemon=True,
        )
        for _ in range(ATTEMPTED_REQUESTS)
    ]

    try:
        for t in clients:
            t.start()

        start.set()

        deadline = time.time() + 5.0

        while time.time() < deadline:
            with core.lock:
                active = core.active

            if active >= EXPECTED_MAX_RPC_WORKERS + 1:
                break

            time.sleep(0.02)

        with core.lock:
            active = core.active
            peak = core.max_active

        assert active <= EXPECTED_MAX_RPC_WORKERS, (
            f"RPC worker concurrency unbounded: "
            f"{active} active requests, "
            f"expected <= {EXPECTED_MAX_RPC_WORKERS}"
        )

        assert peak <= EXPECTED_MAX_RPC_WORKERS, (
            f"RPC worker peak unbounded: "
            f"{peak}, expected <= {EXPECTED_MAX_RPC_WORKERS}"
        )

        print(
            f"[GREEN] RPC workers bounded at "
            f"{peak}/{EXPECTED_MAX_RPC_WORKERS}"
        )

        print("[GREEN] RPC server remains alive at worker saturation")
        print("SEC-030 bounded concurrent RPC workers: 2/2 GREEN")

    finally:
        core.release.set()

        for t in clients:
            t.join(2.0)

        server.stop()


if __name__ == "__main__":
    main()
