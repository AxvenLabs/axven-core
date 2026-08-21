#!/usr/bin/env python3
"""SEC-035: RPC request envelopes must reject unknown top-level fields."""

import http.client
import json

import rpc
from core import AxvenCore


def post_json(host, port, payload):
    raw = json.dumps(payload, separators=(",", ":")).encode()

    conn = http.client.HTTPConnection(host, port, timeout=3)
    try:
        conn.request(
            "POST",
            "/",
            body=raw,
            headers={"Content-Type": "application/json"},
        )
        response = conn.getresponse()
        data = response.read()
        return response.status, json.loads(data)
    finally:
        conn.close()


def main():
    core = AxvenCore()
    server = rpc.RPCServer(core).start()

    try:
        host, port = server.address

        status, body = post_json(
            host,
            port,
            {"method": "get_status", "params": {}},
        )

        assert status == 200 and body.get("ok") is True, (
            f"canonical RPC envelope rejected: HTTP {status}, {body!r}"
        )

        print("[GREEN] canonical RPC request envelope accepted")

        invalid = [
            {"method": "get_status", "params": {}, "extra": True},
            {"method": "get_status", "params": {}, "id": 1},
            {"method": "get_status", "params": {}, "jsonrpc": "2.0"},
            {"method": "get_status", "params": {}, "result": None},
        ]

        rejected = 0

        for payload in invalid:
            status, body = post_json(host, port, payload)

            if (
                status == 400
                and body.get("ok") is False
                and "unknown request field" in body.get("error", "")
            ):
                rejected += 1

        assert rejected == len(invalid), (
            "RPC accepted unknown top-level request fields: "
            f"rejected {rejected}/{len(invalid)}"
        )

        print("[GREEN] unknown RPC request fields rejected")
        print("SEC-035 RPC request envelope validation: 2/2 GREEN")

    finally:
        server.stop()


if __name__ == "__main__":
    main()
