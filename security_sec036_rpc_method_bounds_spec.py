#!/usr/bin/env python3
"""SEC-036: RPC method names must be non-empty and bounded."""

import rpc


class DummyCore:
    def status(self):
        return {"ok": True}


def main():
    dispatcher = rpc.RPCDispatcher(DummyCore())

    # Existing canonical method semantics must remain intact.
    result = dispatcher.call("get_status", {})
    assert result == {"ok": True}, "canonical RPC method behavior changed"
    print("[GREEN] canonical RPC method preserved")

    # Empty method names must not reach normal dispatch semantics.
    try:
        dispatcher.call("", {})
    except rpc.RPCError as e:
        assert str(e) == "invalid method name", (
            f"unexpected RPC error for empty method: {e}"
        )
    else:
        raise AssertionError("empty RPC method accepted")
    print("[GREEN] empty RPC method rejected")

    # Method names are attacker-controlled request data. Bound them before
    # dispatch comparisons.
    oversized = "x" * 257
    try:
        dispatcher.call(oversized, {})
    except rpc.RPCError as e:
        assert str(e) == "invalid method name", (
            f"unexpected RPC error for oversized method: {e}"
        )
    else:
        raise AssertionError("oversized RPC method accepted")
    print("[GREEN] oversized RPC method rejected")

    # Boundary value itself remains structurally valid and therefore reaches
    # the ordinary unknown-method path.
    boundary = "x" * 256
    try:
        dispatcher.call(boundary, {})
    except rpc.RPCError as e:
        assert str(e) == "unknown method", (
            f"256-byte RPC method did not reach normal dispatch: {e}"
        )
    else:
        raise AssertionError("unknown boundary RPC method unexpectedly accepted")
    print("[GREEN] maximum RPC method length reaches normal dispatch")

    print("SEC-036 RPC method name bounds: 4/4 GREEN")


if __name__ == "__main__":
    main()
