#!/usr/bin/env python3
"""SEC-047 RPC peer port bounds regression contract."""

from rpc import RPCDispatcher, RPCError


MAX_PORT = 65535


class FakeCore:
    def __init__(self):
        self.calls = []

    def add_outbound_peer(self, address):
        self.calls.append(("add_peer", address))
        return address

    def remove_outbound_peer(self, address):
        self.calls.append(("remove_peer", address))
        return True


def expect_error(dispatcher, method, params, expected):
    try:
        dispatcher.call(method, params)
    except RPCError as exc:
        assert expected in str(exc), (expected, str(exc))
        return
    raise AssertionError(
        f"RPC accepted invalid {method} parameters: {params!r}"
    )


def main():
    core = FakeCore()
    dispatcher = RPCDispatcher(core)

    result = dispatcher.call(
        "add_peer",
        {"host": "127.0.0.1", "port": 31337},
    )
    assert result == {"host": "127.0.0.1", "port": 31337}
    assert core.calls[-1] == (
        "add_peer",
        ("127.0.0.1", 31337),
    )
    print("[GREEN] canonical RPC add peer port preserved")

    result = dispatcher.call(
        "add_peer",
        {"host": "127.0.0.1", "port": MAX_PORT},
    )
    assert result == {"host": "127.0.0.1", "port": MAX_PORT}
    print("[GREEN] maximum RPC add peer port reaches normal dispatch")

    before = len(core.calls)
    for port in (0, -1, MAX_PORT + 1):
        expect_error(
            dispatcher,
            "add_peer",
            {"host": "127.0.0.1", "port": port},
            "invalid peer port",
        )
    assert len(core.calls) == before
    print("[GREEN] invalid RPC add peer ports rejected")

    result = dispatcher.call(
        "remove_peer",
        {"host": "127.0.0.1", "port": 31337},
    )
    assert result is True
    assert core.calls[-1] == (
        "remove_peer",
        ("127.0.0.1", 31337),
    )
    print("[GREEN] canonical RPC remove peer port preserved")

    result = dispatcher.call(
        "remove_peer",
        {"host": "127.0.0.1", "port": MAX_PORT},
    )
    assert result is True
    print("[GREEN] maximum RPC remove peer port reaches normal dispatch")

    before = len(core.calls)
    for port in (0, -1, MAX_PORT + 1):
        expect_error(
            dispatcher,
            "remove_peer",
            {"host": "127.0.0.1", "port": port},
            "invalid peer port",
        )
    assert len(core.calls) == before
    print("[GREEN] invalid RPC remove peer ports rejected")

    print("SEC-047 RPC peer port bounds: 6/6 GREEN")


if __name__ == "__main__":
    main()
