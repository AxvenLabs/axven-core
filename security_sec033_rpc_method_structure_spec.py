#!/usr/bin/env python3
"""SEC-033: RPC method names must have an explicit string structure."""

import rpc
from core import AxvenCore


def main():
    core = AxvenCore()
    dispatcher = rpc.RPCDispatcher(core)

    invalid_methods = [
        None,
        123,
        True,
        [],
        {},
    ]

    rejected = 0

    for method in invalid_methods:
        try:
            dispatcher.call(method, {})
        except rpc.RPCError as e:
            assert str(e) == "method must be string", (
                f"unexpected RPC error for method {method!r}: {e}"
            )
            rejected += 1

    assert rejected == len(invalid_methods), (
        "RPC dispatcher accepted non-string method: "
        f"rejected {rejected}/{len(invalid_methods)}"
    )

    print("[GREEN] non-string RPC methods rejected")

    try:
        dispatcher.call("__sec033_unknown_method__", {})
    except rpc.RPCError as e:
        assert str(e) == "unknown method", (
            f"string method did not preserve unknown-method behavior: {e}"
        )
    else:
        raise AssertionError("unknown string RPC method unexpectedly accepted")

    print("[GREEN] string RPC method semantics preserved")
    print("SEC-033 RPC method structural validation: 2/2 GREEN")


if __name__ == "__main__":
    main()
