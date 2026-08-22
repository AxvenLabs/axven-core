#!/usr/bin/env python3
"""SEC-044: bound RPC sync_peer batch to the P2P sync limit."""

from rpc import RPCDispatcher, RPCError


MAX_RPC_SYNC_BATCH = 128


class DummyCore:
    def __init__(self):
        self.calls = []

    def sync_peer(self, host, port, batch=128):
        self.calls.append((host, port, batch))
        return batch


def expect_error(dispatcher, params, expected):
    try:
        dispatcher.call("sync_peer", params)
    except RPCError as e:
        assert str(e) == expected, (
            f"unexpected RPC error for {params!r}: {e}"
        )
    else:
        raise AssertionError(
            f"RPC accepted invalid sync_peer parameters: {params!r}"
        )


def main():
    core = DummyCore()
    dispatcher = RPCDispatcher(core)

    # Canonical/default batch must remain valid.
    result = dispatcher.call(
        "sync_peer",
        {"host": "127.0.0.1", "port": 31337},
    )
    assert result == {"accepted": 128}
    assert core.calls[-1] == ("127.0.0.1", 31337, 128)
    print("[GREEN] canonical RPC sync batch preserved")

    # Exact P2P maximum must reach normal dispatch.
    result = dispatcher.call(
        "sync_peer",
        {
            "host": "127.0.0.1",
            "port": 31337,
            "batch": MAX_RPC_SYNC_BATCH,
        },
    )
    assert result == {"accepted": MAX_RPC_SYNC_BATCH}
    assert core.calls[-1][-1] == MAX_RPC_SYNC_BATCH
    print("[GREEN] maximum RPC sync batch reaches normal dispatch")

    # Zero and negative batch sizes must be rejected before Core.
    before = len(core.calls)
    expect_error(
        dispatcher,
        {"host": "127.0.0.1", "port": 31337, "batch": 0},
        "invalid sync batch",
    )
    expect_error(
        dispatcher,
        {"host": "127.0.0.1", "port": 31337, "batch": -1},
        "invalid sync batch",
    )
    assert len(core.calls) == before
    print("[GREEN] non-positive RPC sync batches rejected")

    # One above the P2P protocol bound must be rejected before Core.
    before = len(core.calls)
    expect_error(
        dispatcher,
        {
            "host": "127.0.0.1",
            "port": 31337,
            "batch": MAX_RPC_SYNC_BATCH + 1,
        },
        "invalid sync batch",
    )
    assert len(core.calls) == before
    print("[GREEN] oversized RPC sync batch rejected")

    print("SEC-044 RPC sync batch bounds: 4/4 GREEN")


if __name__ == "__main__":
    main()
