#!/usr/bin/env python3
"""SEC-042: bound RPC mine count before core dispatch."""

from rpc import RPCDispatcher, RPCError


MAX_RPC_MINE_COUNT = 1000


class DummyCore:
    def __init__(self):
        self.calls = []

    def mine(self, count, scheme):
        self.calls.append((count, scheme))
        return {"count": count}


def expect_error(dispatcher, params, expected):
    try:
        dispatcher.call("mine", params)
    except RPCError as e:
        assert str(e) == expected, (
            f"unexpected RPC error for {params!r}: {e}"
        )
    else:
        raise AssertionError(
            f"RPC accepted invalid mine parameters: {params!r}"
        )


def main():
    core = DummyCore()
    dispatcher = RPCDispatcher(core)

    # Canonical/default request must remain valid.
    result = dispatcher.call("mine", {})
    assert result == {"count": 1}
    assert core.calls[-1] == (1, None)
    print("[GREEN] canonical RPC mine count preserved")

    # Exact maximum must still reach normal dispatch.
    result = dispatcher.call(
        "mine",
        {"count": MAX_RPC_MINE_COUNT, "scheme": "N"},
    )
    assert result == {"count": MAX_RPC_MINE_COUNT}
    assert core.calls[-1] == (MAX_RPC_MINE_COUNT, "N")
    print("[GREEN] maximum RPC mine count reaches normal dispatch")

    # Zero and negative counts must be rejected before core dispatch.
    before = len(core.calls)
    expect_error(dispatcher, {"count": 0}, "invalid mine count")
    expect_error(dispatcher, {"count": -1}, "invalid mine count")
    assert len(core.calls) == before
    print("[GREEN] non-positive RPC mine counts rejected")

    # One above the bound must be rejected before core dispatch.
    before = len(core.calls)
    expect_error(
        dispatcher,
        {"count": MAX_RPC_MINE_COUNT + 1},
        "invalid mine count",
    )
    assert len(core.calls) == before
    print("[GREEN] oversized RPC mine count rejected")

    print("SEC-042 RPC mine count bounds: 4/4 GREEN")


if __name__ == "__main__":
    main()
