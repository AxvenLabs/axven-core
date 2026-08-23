#!/usr/bin/env python3
"""SEC-046: bound RPC sync_peer port to the valid TCP port range."""

from rpc import RPCDispatcher, RPCError


class FakeCore:
    def __init__(self):
        self.calls = []

    def sync_peer(self, host, port, batch=128):
        self.calls.append((host, port, batch))
        return 7


def expect_error(dispatcher, params, expected):
    try:
        dispatcher.call("sync_peer", params)
    except (RPCError, ValueError) as exc:
        if expected not in str(exc):
            raise AssertionError(
                f"unexpected RPC error for {params!r}: {exc!r}"
            )
        return

    raise AssertionError(
        f"RPC accepted invalid sync_peer parameters: {params!r}"
    )


def main():
    core = FakeCore()
    dispatcher = RPCDispatcher(core)

    result = dispatcher.call(
        "sync_peer",
        {
            "host": "127.0.0.1",
            "port": 31337,
            "batch": 64,
        },
    )
    assert result == {"accepted": 7}
    assert core.calls[-1] == ("127.0.0.1", 31337, 64)
    print("[GREEN] canonical RPC sync peer port preserved")

    result = dispatcher.call(
        "sync_peer",
        {
            "host": "127.0.0.1",
            "port": 65535,
            "batch": 1,
        },
    )
    assert result == {"accepted": 7}
    assert core.calls[-1] == ("127.0.0.1", 65535, 1)
    print("[GREEN] maximum RPC sync peer port reaches normal dispatch")

    before = len(core.calls)
    expect_error(
        dispatcher,
        {
            "host": "127.0.0.1",
            "port": 0,
            "batch": 1,
        },
        "invalid sync peer port",
    )
    assert len(core.calls) == before
    print("[GREEN] zero RPC sync peer port rejected")

    before = len(core.calls)
    expect_error(
        dispatcher,
        {
            "host": "127.0.0.1",
            "port": -1,
            "batch": 1,
        },
        "invalid sync peer port",
    )
    assert len(core.calls) == before
    print("[GREEN] negative RPC sync peer port rejected")

    before = len(core.calls)
    expect_error(
        dispatcher,
        {
            "host": "127.0.0.1",
            "port": 65536,
            "batch": 1,
        },
        "invalid sync peer port",
    )
    assert len(core.calls) == before
    print("[GREEN] oversized RPC sync peer port rejected")

    print("SEC-046 RPC sync peer port bounds: 5/5 GREEN")


if __name__ == "__main__":
    main()
