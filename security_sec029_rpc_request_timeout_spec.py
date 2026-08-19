#!/usr/bin/env python3
"""SEC-029 stalled RPC request timeout regression contract."""

import socket
import time

import axven
from core import AxvenCore
from rpc import RPCServer


EXPECTED_RPC_REQUEST_TIMEOUT = 5.0


def main():
    core = AxvenCore()
    server = RPCServer(core, port=0).start()

    stalled = None
    probe = None

    try:
        stalled = socket.create_connection(server.address, timeout=1.0)
        stalled.settimeout(EXPECTED_RPC_REQUEST_TIMEOUT + 2.0)

        partial_body = b'{"method":"get_status"'
        declared = len(partial_body) + 100

        request = (
            b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {declared}\r\n".encode()
            + b"Connection: close\r\n"
            + b"\r\n"
            + partial_body
        )

        stalled.sendall(request)

        started = time.time()

        # A bounded RPC server must eventually close a client that never
        # finishes the declared request body.
        try:
            data = stalled.recv(4096)
            elapsed = time.time() - started

            assert elapsed <= EXPECTED_RPC_REQUEST_TIMEOUT + 1.0, (
                f"stalled RPC request survived {elapsed:.2f}s"
            )

            # A timed-out request may be closed immediately or receive an
            # HTTP error response before the connection is closed.
            if data:
                assert data.startswith(b"HTTP/"), (
                    f"stalled RPC connection returned unexpected data: "
                    f"{data[:32]!r}"
                )

        except socket.timeout as exc:
            elapsed = time.time() - started
            raise AssertionError(
                f"stalled RPC request remained open for "
                f"{elapsed:.2f}s without server timeout"
            ) from exc

        print("[GREEN] stalled RPC request timed out")

        # Listener must remain usable after timing out the stalled request.
        probe = socket.create_connection(server.address, timeout=1.0)
        probe.settimeout(2.0)

        body = b'{"method":"get_status"}'
        probe.sendall(
            b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n"
            + b"\r\n"
            + body
        )

        response = b""
        while True:
            chunk = probe.recv(4096)
            if not chunk:
                break
            response += chunk

        assert b"200 OK" in response
        assert b'"ok":true' in response

        print("[GREEN] RPC listener survives stalled request")
        print("SEC-029 RPC stalled-request timeout: 2/2 GREEN")

    finally:
        for sock in (stalled, probe):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        server.stop()


if __name__ == "__main__":
    main()
