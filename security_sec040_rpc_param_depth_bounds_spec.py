#!/usr/bin/env python3
"""SEC-040: bound nested RPC parameter value depth."""

from rpc import RPCDispatcher, RPCError


MAX_RPC_PARAM_DEPTH = 16


class DummyCore:
    def status(self):
        return {"ok": True}


def nested_value(depth):
    value = "leaf"
    for _ in range(depth):
        value = {"nested": value}
    return value


def main():
    dispatcher = RPCDispatcher(DummyCore())

    # Canonical scalar parameter values must remain valid.
    result = dispatcher.call(
        "get_status",
        {
            "string": "value",
            "integer": 1,
            "boolean": True,
            "null": None,
        },
    )
    assert result == {"ok": True}
    print("[GREEN] canonical RPC parameter values preserved")

    # Exactly the maximum permitted nesting depth must pass structural
    # validation and reach normal dispatch.
    maximum = {"value": nested_value(MAX_RPC_PARAM_DEPTH)}
    try:
        dispatcher.call("unknown_method", maximum)
    except RPCError as e:
        assert str(e) == "unknown method", (
            f"maximum RPC parameter depth did not reach dispatch: {e}"
        )
    else:
        raise AssertionError("unknown method unexpectedly succeeded")
    print("[GREEN] maximum RPC parameter depth reaches normal dispatch")

    # One level beyond the bound must be rejected before dispatch.
    oversized = {"value": nested_value(MAX_RPC_PARAM_DEPTH + 1)}
    try:
        dispatcher.call("unknown_method", oversized)
    except RPCError as e:
        assert str(e) == "param nesting too deep", (
            f"unexpected RPC error for deep parameter value: {e}"
        )
    else:
        raise AssertionError(
            "RPC accepted parameter value beyond maximum nesting depth"
        )
    print("[GREEN] oversized RPC parameter depth rejected")

    # Lists participate in the same nesting budget.
    deep_list = "leaf"
    for _ in range(MAX_RPC_PARAM_DEPTH + 1):
        deep_list = [deep_list]

    try:
        dispatcher.call("unknown_method", {"value": deep_list})
    except RPCError as e:
        assert str(e) == "param nesting too deep", (
            f"unexpected RPC error for deep list parameter: {e}"
        )
    else:
        raise AssertionError(
            "RPC accepted deeply nested list parameter value"
        )
    print("[GREEN] deeply nested RPC list value rejected")

    print("SEC-040 RPC parameter depth bounds: 4/4 GREEN")


if __name__ == "__main__":
    main()
