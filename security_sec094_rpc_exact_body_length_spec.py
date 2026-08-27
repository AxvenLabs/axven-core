#!/usr/bin/env python3
"""SEC-094 requires RPC request bytes to exactly match Content-Length."""

import socket

import rpc


class ProbeCore:
    def __init__(self):
        self.stop_calls = 0

    def request_shutdown(self):
        self.stop_calls += 1
        return {"stopping": True}


def raw_post(address, body, declared_length):
    port = address[1]
    sock = socket.create_connection(address, timeout=2.0)
    sock.settimeout(2.0)
    try:
        request = (
            b"POST / HTTP/1.1\r\n"
            + f"Host: 127.0.0.1:{port}\r\n".encode()
            + b"Content-Type: application/json\r\n"
            + f"Content-Length: {declared_length}\r\n".encode()
            + b"Connection: close\r\n"
            + b"\r\n"
            + body
        )
        sock.sendall(request)
        sock.shutdown(socket.SHUT_WR)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        return response
    finally:
        sock.close()


def main():
    core = ProbeCore()
    server = rpc.RPCServer(core, port=0).start()
    try:
        body = b'{"method":"stop"}'

        truncated = raw_post(server.address, body, len(body) + 32)
        assert b" 400 " in truncated.split(b"\r\n", 1)[0], truncated[:200]
        assert b"incomplete request body" in truncated, truncated[:400]
        print("[GREEN] truncated RPC body rejected")

        assert core.stop_calls == 0, "truncated operator request reached dispatch"
        print("[GREEN] truncated operator request blocked before dispatch")

        exact = raw_post(server.address, body, len(body))
        assert b" 200 " in exact.split(b"\r\n", 1)[0], exact[:200]
        assert core.stop_calls == 1, "exact RPC body did not dispatch exactly once"
        print("[GREEN] exact-length RPC body preserved")

        print("SEC-094 exact RPC request body length: 3/3 GREEN")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
