#!/usr/bin/env python3
"""SEC-039: RPC JSON objects must reject duplicate keys."""

import http.client
import json

import rpc
from core import AxvenCore


def post_raw(host, port, raw):
    conn = http.client.HTTPConnection(host, port, timeout=3)

    try:
        conn.request(
            "POST",
            "/",
            body=raw,
            headers={"Content-Type": "application/json"},
        )

        response = conn.getresponse()
        body = response.read()

        try:
            decoded = json.loads(body)
        except Exception:
            decoded = None

        return response.status, decoded
    finally:
        conn.close()


def main():
    core = AxvenCore()
    server = rpc.RPCServer(core).start()

    try:
        host, port = server.address

        status, body = post_raw(
            host,
            port,
            b'{"method":"get_status","params":{}}',
        )

        assert status == 200 and body.get("ok") is True, (
            f"canonical RPC request rejected: HTTP {status}, {body!r}"
        )

        print("[GREEN] canonical JSON object preserved")

        duplicate_method = (
            b'{"method":"unknown_method",'
            b'"method":"get_status","params":{}}'
        )

        status, body = post_raw(host, port, duplicate_method)

        assert (
            status == 400
            and body.get("ok") is False
            and "duplicate JSON key" in body.get("error", "")
        ), (
            "RPC accepted duplicate top-level JSON key: "
            f"HTTP {status}, {body!r}"
        )

        print("[GREEN] duplicate top-level JSON key rejected")

        duplicate_param = (
            b'{"method":"get_status",'
            b'"params":{"probe":1,"probe":2}}'
        )

        status, body = post_raw(host, port, duplicate_param)

        assert (
            status == 400
            and body.get("ok") is False
            and "duplicate JSON key" in body.get("error", "")
        ), (
            "RPC accepted duplicate params JSON key: "
            f"HTTP {status}, {body!r}"
        )

        print("[GREEN] duplicate RPC param JSON key rejected")
        print("SEC-039 RPC duplicate JSON keys: 3/3 GREEN")

    finally:
        server.stop()


if __name__ == "__main__":
    main()
