#!/usr/bin/env python3
"""SEC-032: RPC params must be absent/null or a JSON object."""

import rpc


class FakeCore:
    def status(self):
        return {"ok": True}


def main():
    dispatcher = rpc.RPCDispatcher(FakeCore())

    # Missing/None params remains valid and behaves as an empty object.
    result = dispatcher.call("get_status", None)
    assert result == {"ok": True}
    print("[GREEN] null RPC params accepted as empty object")

    invalid_params = [
        [],
        [1, 2],
        "text",
        123,
        True,
    ]

    rejected = 0

    for params in invalid_params:
        try:
            dispatcher.call("get_status", params)
        except rpc.RPCError:
            rejected += 1

    assert rejected == len(invalid_params), (
        "RPC dispatcher accepted non-object params: "
        f"rejected {rejected}/{len(invalid_params)}"
    )

    print("[GREEN] non-object RPC params rejected")
    print("SEC-032 RPC params structural validation: 2/2 GREEN")


if __name__ == "__main__":
    main()
