#!/usr/bin/env python3
"""SEC-040: bound nested RPC parameter value depth."""

from rpc import RPCDispatcher, RPCError


MAX_RPC_PARAM_DEPTH = 16


class DummyCore:
    pass


def nested_value(depth):
    value = "leaf"
    for _ in range(depth):
        value = {"nested": value}
    return value


def main():
    dispatcher = RPCDispatcher(DummyCore())

    # Ordinary scalar values must pass the SEC-040 depth gate.  The probe uses
    # an unknown method so SEC-171 cannot mistake arbitrary test-only fields
    # for a production method vocabulary.
    try:
        dispatcher.call(
            "__sec040_unknown_method__",
            {
                "string": "value",
                "integer": 1,
                "boolean": True,
                "null": None,
            },
        )
    except RPCError as e:
        assert str(e) == "unknown method", (
            f"ordinary scalar params did not pass structural depth validation: {e}"
        )
    else:
        raise AssertionError("unknown method unexpectedly succeeded")
    print("[GREEN] ordinary RPC scalar values pass depth gate")

    # Exactly the maximum permitted nesting depth must pass structural
    # validation and reach the later unknown-method gate.
    maximum = {"value": nested_value(MAX_RPC_PARAM_DEPTH)}
    try:
        dispatcher.call("unknown_method", maximum)
    except RPCError as e:
        assert str(e) == "unknown method", (
            f"maximum RPC parameter depth did not pass structural gate: {e}"
        )
    else:
        raise AssertionError("unknown method unexpectedly succeeded")
    print("[GREEN] maximum RPC parameter depth passes structural gate")

    # One level beyond the bound must be rejected before method-schema work.
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
