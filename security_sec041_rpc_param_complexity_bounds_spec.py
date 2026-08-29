#!/usr/bin/env python3
"""SEC-041: bound total RPC parameter value complexity."""

from rpc import RPCDispatcher, RPCError


MAX_RPC_PARAM_NODES = 4096


class DummyCore:
    pass


def main():
    dispatcher = RPCDispatcher(DummyCore())

    # An ordinary scalar value must pass the SEC-041 complexity gate and reach
    # the later unknown-method gate without being treated as a production
    # method-specific parameter vocabulary.
    try:
        dispatcher.call("__sec041_unknown_method__", {"scheme": "N"})
    except RPCError as e:
        assert str(e) == "unknown method", (
            f"ordinary scalar param did not pass complexity validation: {e}"
        )
    else:
        raise AssertionError("unknown method unexpectedly succeeded")
    print("[GREEN] ordinary RPC parameter complexity passes structural gate")

    # Exactly the maximum node budget must pass structural validation
    # and reach the later unknown-method gate.
    #
    # The outer list itself counts as one node, so 4095 scalar children
    # produce exactly 4096 nodes.
    maximum = {"payload": [0] * (MAX_RPC_PARAM_NODES - 1)}
    try:
        dispatcher.call("unknown_method", maximum)
    except RPCError as e:
        assert str(e) == "unknown method", (
            f"maximum RPC parameter complexity did not pass structural gate: {e}"
        )
    else:
        raise AssertionError("unknown method unexpectedly succeeded")
    print("[GREEN] maximum RPC parameter complexity passes structural gate")

    # One node beyond the budget must be rejected before method-schema work.
    oversized = {"payload": [0] * MAX_RPC_PARAM_NODES}
    try:
        dispatcher.call("unknown_method", oversized)
    except RPCError as e:
        assert str(e) == "params too complex", (
            f"unexpected RPC error for oversized parameter complexity: {e}"
        )
    else:
        raise AssertionError(
            "RPC accepted parameter structure beyond complexity budget"
        )
    print("[GREEN] oversized RPC parameter complexity rejected")

    # Wide dictionaries nested inside a parameter value must share the
    # same total budget; the protection must not be list-specific.
    oversized_dict = {
        "payload": {f"k{i}": i for i in range(MAX_RPC_PARAM_NODES)}
    }
    try:
        dispatcher.call("unknown_method", oversized_dict)
    except RPCError as e:
        assert str(e) == "params too complex", (
            f"unexpected RPC error for oversized dict complexity: {e}"
        )
    else:
        raise AssertionError(
            "RPC accepted oversized nested dictionary"
        )
    print("[GREEN] oversized RPC dictionary complexity rejected")

    print("SEC-041 RPC parameter complexity bounds: 4/4 GREEN")


if __name__ == "__main__":
    main()
