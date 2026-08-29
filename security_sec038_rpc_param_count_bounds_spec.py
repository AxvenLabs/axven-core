#!/usr/bin/env python3
"""SEC-038: bound the number of RPC parameter keys."""

from rpc import RPCDispatcher, RPCError


MAX_RPC_PARAMS = 64


class DummyCore:
    def recent_blocks(self, limit):
        return [limit]


def main():
    dispatcher = RPCDispatcher(DummyCore())

    # A canonical one-parameter request remains valid under SEC-171.
    result = dispatcher.call("get_recent_blocks", {"limit": 1})
    assert result == [1]
    print("[GREEN] canonical RPC parameter count preserved")

    # Exactly the maximum number of parameters must pass structural
    # validation and reach the later unknown-method gate.
    maximum = {f"k{i}": i for i in range(MAX_RPC_PARAMS)}
    try:
        dispatcher.call("unknown_method", maximum)
    except RPCError as e:
        assert str(e) == "unknown method", (
            f"maximum valid RPC parameter count did not pass structural gate: {e}"
        )
    else:
        raise AssertionError("unknown method unexpectedly succeeded")
    print("[GREEN] maximum RPC parameter count passes structural gate")

    # One parameter beyond the bound must be rejected before method-schema
    # or dispatch work.
    oversized = {f"k{i}": i for i in range(MAX_RPC_PARAMS + 1)}
    try:
        dispatcher.call("unknown_method", oversized)
    except RPCError as e:
        assert str(e) == "too many params", (
            f"unexpected RPC error for oversized params: {e}"
        )
    else:
        raise AssertionError(
            f"RPC accepted {len(oversized)} parameters; expected bound {MAX_RPC_PARAMS}"
        )
    print("[GREEN] oversized RPC parameter count rejected")

    print("SEC-038 RPC parameter count bounds: 3/3 GREEN")


if __name__ == "__main__":
    main()
