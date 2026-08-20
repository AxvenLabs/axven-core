#!/usr/bin/env python3
"""SEC-031: RPC request bodies must have an explicit bounded byte budget."""

import http.client

import rpc
from core import AxvenCore


EXPECTED_MAX_RPC_REQUEST_BYTES = 2 * 1024 * 1024


def main():
    assert hasattr(rpc, "MAX_RPC_REQUEST_BYTES"), (
        "RPC request byte limit is not exposed as a security constant"
    )
    assert rpc.MAX_RPC_REQUEST_BYTES == EXPECTED_MAX_RPC_REQUEST_BYTES, (
        f"unexpected RPC request byte limit: "
        f"{rpc.MAX_RPC_REQUEST_BYTES} != {EXPECTED_MAX_RPC_REQUEST_BYTES}"
    )

    print(
        "[GREEN] RPC request byte budget pinned at "
        f"{EXPECTED_MAX_RPC_REQUEST_BYTES}"
    )

    core = AxvenCore()
    server = rpc.RPCServer(core).start()

    try:
        host, port = server.address

        oversized = b"x" * (EXPECTED_MAX_RPC_REQUEST_BYTES + 1)

        conn = http.client.HTTPConnection(host, port, timeout=3)
        try:
            conn.request(
                "POST",
                "/",
                body=oversized,
                headers={"Content-Type": "application/json"},
            )
            response = conn.getresponse()
            response.read()

            assert response.status == 400, (
                f"oversized RPC request returned HTTP {response.status}"
            )
        finally:
            conn.close()

        print("[GREEN] oversized RPC request rejected")

        body = b'{"method":"get_status","params":{}}'

        conn = http.client.HTTPConnection(host, port, timeout=3)
        try:
            conn.request(
                "POST",
                "/",
                body=body,
                headers={"Content-Type": "application/json"},
            )
            response = conn.getresponse()
            data = response.read()

            assert response.status == 200, (
                f"normal RPC request returned HTTP {response.status}: "
                f"{data[:200]!r}"
            )
        finally:
            conn.close()

        print("[GREEN] normal RPC request preserved")
        print("SEC-031 bounded RPC request body: 3/3 GREEN")

    finally:
        server.stop()


if __name__ == "__main__":
    main()
