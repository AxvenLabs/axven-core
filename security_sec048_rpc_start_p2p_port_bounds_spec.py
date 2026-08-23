#!/usr/bin/env python3
"""SEC-048 RPC start_p2p port bounds regression contract."""

import rpc


class FakeCore:
    def __init__(self):
        self.calls = []

    def start_p2p(self, host, port):
        self.calls.append((host, port))
        return (host, port)


def expect_error(dispatcher, params, expected):
    before = len(dispatcher.core.calls)

    try:
        dispatcher.call("start_p2p", params)
    except rpc.RPCError as exc:
        assert str(exc) == expected, (str(exc), expected)
    except (TypeError, ValueError, OverflowError):
        pass
    else:
        raise AssertionError(
            f"RPC accepted invalid start_p2p parameters: {params!r}"
        )

    assert len(dispatcher.core.calls) == before


def main():
    core = FakeCore()
    dispatcher = rpc.RPCDispatcher(core)

    result = dispatcher.call(
        "start_p2p",
        {
            "host": "127.0.0.1",
            "port": 31337,
        },
    )
    assert result == {"host": "127.0.0.1", "port": 31337}
    assert core.calls[-1] == ("127.0.0.1", 31337)
    print("[GREEN] canonical RPC start_p2p port preserved")

    result = dispatcher.call(
        "start_p2p",
        {
            "host": "127.0.0.1",
            "port": 0,
        },
    )
    assert result == {"host": "127.0.0.1", "port": 0}
    assert core.calls[-1] == ("127.0.0.1", 0)
    print("[GREEN] ephemeral RPC start_p2p port preserved")

    result = dispatcher.call(
        "start_p2p",
        {
            "host": "127.0.0.1",
            "port": 65535,
        },
    )
    assert result == {"host": "127.0.0.1", "port": 65535}
    assert core.calls[-1] == ("127.0.0.1", 65535)
    print("[GREEN] maximum RPC start_p2p port reaches normal dispatch")

    expect_error(
        dispatcher,
        {
            "host": "127.0.0.1",
            "port": -1,
        },
        "invalid start_p2p port",
    )
    print("[GREEN] negative RPC start_p2p port rejected")

    expect_error(
        dispatcher,
        {
            "host": "127.0.0.1",
            "port": 65536,
        },
        "invalid start_p2p port",
    )
    print("[GREEN] oversized RPC start_p2p port rejected")

    print("SEC-048 RPC start_p2p port bounds: 5/5 GREEN")


if __name__ == "__main__":
    main()
