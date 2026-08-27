#!/usr/bin/env python3
"""SEC-092 blocks DNS-rebinding Host headers at the loopback RPC boundary."""

import json
import socket

import rpc


class _ProbeCore:
    def __init__(self):
        self.stop_calls = 0
        self.status_calls = 0

    def status(self):
        self.status_calls += 1
        return {"probe": "ok"}

    def request_shutdown(self):
        self.stop_calls += 1
        return {"stopping": True}


def _request(address, host_lines, method):
    body = json.dumps({"method": method, "params": {}}).encode()
    request = b"POST / HTTP/1.1\r\n"
    for line in host_lines:
        request += b"Host: " + line.encode("ascii") + b"\r\n"
    request += (
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n"
        + b"\r\n"
        + body
    )

    sock = socket.create_connection(address, timeout=1.0)
    try:
        sock.settimeout(2.0)
        sock.sendall(request)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        return response
    finally:
        sock.close()


def _status(response):
    return int(response.split(b" ", 2)[1])


def main():
    checks = []
    core = _ProbeCore()
    server = rpc.RPCServer(core, port=0).start()
    port = server.address[1]

    try:
        response = _request(
            server.address,
            [f"attacker.example:{port}"],
            "stop",
        )
        assert _status(response) == 400
        assert core.stop_calls == 0
        checks.append("foreign Host rejected before RPC dispatch")
        print("[GREEN] foreign Host rejected before RPC dispatch")

        response = _request(
            server.address,
            [f"127.0.0.1.attacker.example:{port}"],
            "stop",
        )
        assert _status(response) == 400
        assert core.stop_calls == 0
        checks.append("loopback-lookalike Host rejected")
        print("[GREEN] loopback-lookalike Host rejected")

        response = _request(
            server.address,
            [f"localhost:{port}", f"127.0.0.1:{port}"],
            "stop",
        )
        assert _status(response) == 400
        assert core.stop_calls == 0
        checks.append("duplicate Host headers rejected")
        print("[GREEN] duplicate Host headers rejected")

        response = _request(server.address, [], "stop")
        assert _status(response) == 400
        assert core.stop_calls == 0
        checks.append("missing Host rejected")
        print("[GREEN] missing Host rejected")

        response = _request(
            server.address,
            [f"127.0.0.1:{port}"],
            "get_status",
        )
        assert _status(response) == 200
        assert core.status_calls == 1
        checks.append("canonical IPv4 loopback Host preserved")
        print("[GREEN] canonical IPv4 loopback Host preserved")

        response = _request(
            server.address,
            [f"localhost:{port}"],
            "get_status",
        )
        assert _status(response) == 200
        assert core.status_calls == 2
        checks.append("canonical localhost Host preserved")
        print("[GREEN] canonical localhost Host preserved")

        response = _request(
            server.address,
            [f"evil@localhost:{port}"],
            "stop",
        )
        assert _status(response) == 400
        assert core.stop_calls == 0
        checks.append("userinfo-style Host rejected")
        print("[GREEN] userinfo-style Host rejected")

        print(
            f"SEC-092 RPC Host-header guard: "
            f"{len(checks)}/{len(checks)} GREEN"
        )
    finally:
        server.stop()


if __name__ == "__main__":
    main()
