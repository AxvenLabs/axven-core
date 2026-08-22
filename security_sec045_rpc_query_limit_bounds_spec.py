#!/usr/bin/env python3
"""SEC-045 bounded RPC query limit regression contract."""

import rpc


class DummyCore:
    def __init__(self):
        self.calls = []

    def recent_blocks(self, limit=20):
        self.calls.append(("recent_blocks", limit))
        return {"limit": limit}

    def mempool_view(self, limit=100):
        self.calls.append(("mempool_view", limit))
        return {"limit": limit}


def expect_error(dispatcher, method, params, expected):
    try:
        dispatcher.call(method, params)
    except rpc.RPCError as exc:
        assert str(exc) == expected, (str(exc), expected)
        return
    raise AssertionError(
        f"RPC accepted invalid {method} parameters: {params!r}"
    )


def main():
    core = DummyCore()
    dispatcher = rpc.RPCDispatcher(core)

    # Canonical/default behavior must remain unchanged.
    result = dispatcher.call("get_recent_blocks", {})
    assert result["limit"] == 20
    assert core.calls[-1] == ("recent_blocks", 20)

    result = dispatcher.call("get_mempool", {})
    assert result["limit"] == 100
    assert core.calls[-1] == ("mempool_view", 100)

    print("[GREEN] canonical RPC query limits preserved")

    # Maximum valid values must still reach normal dispatch.
    result = dispatcher.call(
        "get_recent_blocks",
        {"limit": 200},
    )
    assert result["limit"] == 200
    assert core.calls[-1] == ("recent_blocks", 200)

    result = dispatcher.call(
        "get_mempool",
        {"limit": 500},
    )
    assert result["limit"] == 500
    assert core.calls[-1] == ("mempool_view", 500)

    print("[GREEN] maximum RPC query limits reach normal dispatch")

    before = len(core.calls)

    for value in (0, -1):
        expect_error(
            dispatcher,
            "get_recent_blocks",
            {"limit": value},
            "invalid recent blocks limit",
        )

    assert len(core.calls) == before
    print("[GREEN] non-positive recent-block limits rejected")

    before = len(core.calls)

    expect_error(
        dispatcher,
        "get_recent_blocks",
        {"limit": 201},
        "invalid recent blocks limit",
    )

    assert len(core.calls) == before
    print("[GREEN] oversized recent-block limit rejected")

    before = len(core.calls)

    for value in (0, -1):
        expect_error(
            dispatcher,
            "get_mempool",
            {"limit": value},
            "invalid mempool limit",
        )

    assert len(core.calls) == before
    print("[GREEN] non-positive mempool limits rejected")

    before = len(core.calls)

    expect_error(
        dispatcher,
        "get_mempool",
        {"limit": 501},
        "invalid mempool limit",
    )

    assert len(core.calls) == before
    print("[GREEN] oversized mempool limit rejected")

    print("SEC-045 RPC query limit bounds: 6/6 GREEN")


if __name__ == "__main__":
    main()
