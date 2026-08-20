#!/usr/bin/env python3
"""SEC-034: RPC POST bodies must use an application/json content type."""

import http.client
import json

import rpc
from core import AxvenCore


def request(host, port, content_type):
    body = json.dumps({
        "method": "get_status",
        "params": {},
    }).encode()

    conn = http.client.HTTPConnection(host, port, timeout=3)

    try:
        headers = {
            "Content-Length": str(len(body)),
        }

        if content_type is not None:
            headers["Content-Type"] = content_type

        conn.request(
            "POST",
            "/",
            body=body,
            headers=headers,
        )

        response = conn.getresponse()
        data = response.read()
        return response.status, data

    finally:
        conn.close()


def main():
    core = AxvenCore()
    server = rpc.RPCServer(core).start()

    try:
        host, port = server.address

        status, _ = request(
            host,
            port,
            "application/json",
        )

        assert status == 200, (
            f"application/json RPC request returned HTTP {status}"
        )

        print("[GREEN] application/json RPC request accepted")

        status, _ = request(
            host,
            port,
            "application/json; charset=utf-8",
        )

        assert status == 200, (
            f"JSON content type with charset returned HTTP {status}"
        )

        print("[GREEN] JSON content type with charset accepted")

        rejected = 0

        for content_type in (
            None,
            "text/plain",
            "application/octet-stream",
            "text/html",
        ):
            status, _ = request(
                host,
                port,
                content_type,
            )

            if status == 400:
                rejected += 1

        assert rejected == 4, (
            "RPC accepted non-JSON content types: "
            f"rejected {rejected}/4"
        )

        print("[GREEN] non-JSON RPC content types rejected")
        print("SEC-034 RPC content-type validation: 3/3 GREEN")

    finally:
        server.stop()


if __name__ == "__main__":
    main()
