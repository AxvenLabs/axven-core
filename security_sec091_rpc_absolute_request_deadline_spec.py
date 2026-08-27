#!/usr/bin/env python3
"""SEC-091 bounds total RPC request receive time, including headers and body."""

import socket
import threading
import time

from core import AxvenCore
import rpc


TEST_DEADLINE = 0.35
TRICKLE_INTERVAL = 0.07
MAX_OBSERVED_SECONDS = 1.0


def _trickle(sock, payload):
    try:
        for byte in payload:
            sock.sendall(bytes((byte,)))
            time.sleep(TRICKLE_INTERVAL)
    except OSError:
        pass


def _closed_within(sock, payload, label):
    sender = threading.Thread(target=_trickle, args=(sock, payload), daemon=True)
    started = time.monotonic()
    sender.start()
    sock.settimeout(MAX_OBSERVED_SECONDS + 0.5)
    try:
        sock.recv(4096)
    except OSError as exc:
        if isinstance(exc, socket.timeout):
            raise AssertionError(f"{label} escaped absolute RPC receive deadline") from exc
    elapsed = time.monotonic() - started
    assert elapsed < MAX_OBSERVED_SECONDS, f"{label} survived {elapsed:.3f}s"
    print(f"[GREEN] {label} bounded at {elapsed:.3f}s")


def _healthy_request(address):
    body = b'{"method":"get_status"}'
    request = (
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
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
        assert b"200 OK" in response
        assert b'"ok":true' in response
    finally:
        sock.close()


def main():
    original_deadline = rpc.RPC_REQUEST_DEADLINE
    original_timeout = rpc.RPC_REQUEST_TIMEOUT
    rpc.RPC_REQUEST_DEADLINE = TEST_DEADLINE
    rpc.RPC_REQUEST_TIMEOUT = 1.0

    core = AxvenCore()
    server = rpc.RPCServer(core, port=0).start()
    sockets = []

    try:
        header_sock = socket.create_connection(server.address, timeout=1.0)
        sockets.append(header_sock)
        header_payload = (
            b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 23\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b'{"method":"get_status"}'
        )
        _closed_within(header_sock, header_payload, "RPC header trickle")

        body_sock = socket.create_connection(server.address, timeout=1.0)
        sockets.append(body_sock)
        body = b'{"method":"get_status"}'
        body_sock.sendall(
            b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n"
            + b"\r\n"
        )
        _closed_within(body_sock, body, "RPC body trickle")

        time.sleep(0.1)
        _healthy_request(server.address)
        print("[GREEN] RPC listener remains healthy after receive deadlines")
        print("SEC-091 absolute RPC request deadline: 3/3 GREEN")

    finally:
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass
        server.stop()
        rpc.RPC_REQUEST_DEADLINE = original_deadline
        rpc.RPC_REQUEST_TIMEOUT = original_timeout


if __name__ == "__main__":
    main()
