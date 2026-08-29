#!/usr/bin/env python3
"""SEC-127 bound RPC JSON nesting before json.loads."""

import http.client
import inspect
import json

import rpc


class Core:
    def status(self):
        return {"height": 7, "tip_hash": "0" * 64}


def post_raw(address, raw):
    conn = http.client.HTTPConnection(address[0], address[1], timeout=2)
    try:
        conn.request(
            "POST",
            "/",
            body=raw,
            headers={"Content-Type": "application/json"},
        )
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def nested_value(levels):
    value = 0
    for _ in range(levels):
        value = [value]
    return value


def main():
    checks = []

    def green(name, condition):
        assert condition, name
        checks.append(name)
        print("[GREEN]", name)

    green(
        "RPC raw JSON nesting limit pinned above canonical parameter depth",
        rpc.MAX_RPC_JSON_NESTING_DEPTH == 32,
    )

    at_limit = (
        b'{"method":"get_status","x":' + b'[' * 31 + b'0' + b']' * 31 + b'}'
    )
    rpc._preflight_json_nesting(at_limit)
    green("exact raw nesting-depth boundary is accepted by preflight", True)

    too_deep = (
        b'{"method":"get_status","x":' + b'[' * 32 + b'0' + b']' * 32 + b'}'
    )
    try:
        rpc._preflight_json_nesting(too_deep)
        over_depth_rejected = False
    except rpc.RPCError as exc:
        over_depth_rejected = "nesting depth exceeded" in str(exc)
    green("over-depth raw RPC JSON is rejected", over_depth_rejected)

    string_payload = {
        "method": "get_status",
        "params": {
            "text": ("[{" * 80) + '\\\"quoted\\\\text' + ("}]" * 80),
        },
    }
    rpc._preflight_json_nesting(
        json.dumps(string_payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    green("container-looking bytes inside JSON strings are ignored", True)

    try:
        rpc._preflight_json_nesting(b'}' * 64 + b'[' * 33)
        unmatched_bypass_blocked = False
    except rpc.RPCError as exc:
        unmatched_bypass_blocked = "nesting depth exceeded" in str(exc)
    green("unmatched closers cannot reset depth and bypass the limit", unmatched_bypass_blocked)

    try:
        rpc._preflight_json_nesting(b'{' + b']' * 64 + b'[' * 32)
        mismatch_bypass_blocked = False
    except rpc.RPCError as exc:
        mismatch_bypass_blocked = "nesting depth exceeded" in str(exc)
    green("mismatched closers cannot pop unlike openers", mismatch_bypass_blocked)

    server = rpc.RPCServer(Core()).start()
    try:
        parser_calls = []
        original_loads = rpc.json.loads

        def trap_loads(*args, **kwargs):
            parser_calls.append(1)
            raise AssertionError("json.loads must not run for over-depth RPC input")

        rpc.json.loads = trap_loads
        try:
            status, _ = post_raw(server.address, too_deep)
        finally:
            rpc.json.loads = original_loads
        green(
            "production HTTP path rejects over-depth input before json.loads",
            status == 400 and not parser_calls,
        )

        parser_calls = []

        def counting_loads(*args, **kwargs):
            parser_calls.append(1)
            return original_loads(*args, **kwargs)

        rpc.json.loads = counting_loads
        try:
            malformed_status, _ = post_raw(server.address, b'{"method":]')
        finally:
            rpc.json.loads = original_loads
        green(
            "ordinary shallow malformed JSON still reaches canonical parser",
            malformed_status == 400 and len(parser_calls) == 1,
        )

        healthy_raw = json.dumps(
            {"method": "get_status", "params": {}},
            separators=(",", ":"),
        ).encode("utf-8")
        healthy_status, healthy_body = post_raw(server.address, healthy_raw)
        healthy = json.loads(healthy_body)
        green(
            "healthy canonical RPC request remains available",
            healthy_status == 200
            and healthy.get("ok") is True
            and healthy.get("result", {}).get("height") == 7,
        )
    finally:
        server.stop()

    dispatcher = rpc.RPCDispatcher(Core())
    try:
        dispatcher.call("unknown_method", {"x": nested_value(16)})
        shallow_reaches_grammar = False
    except rpc.RPCError as exc:
        shallow_reaches_grammar = str(exc) == "unknown method"
    try:
        dispatcher.call("unknown_method", {"x": nested_value(17)})
        parsed_depth_rejected = False
    except rpc.RPCError as exc:
        parsed_depth_rejected = "nesting too deep" in str(exc)
    green(
        "existing parsed parameter depth contract remains independently enforced",
        shallow_reaches_grammar and parsed_depth_rejected,
    )

    handler_src = inspect.getsource(rpc._handler)
    preflight_at = handler_src.index("_preflight_json_nesting(raw_request)")
    loads_at = handler_src.index("json.loads(raw_request")
    cancel_at = handler_src.index("_cancel_request_deadline()", preflight_at - 120)
    green(
        "production parser order is receive deadline cancel then preflight then json.loads",
        cancel_at < preflight_at < loads_at,
    )

    try:
        rpc.RPCServer(Core(), host="0.0.0.0", port=0)
        loopback_only = False
    except ValueError:
        loopback_only = True
    green("RPC listener remains loopback-only", loopback_only)

    print(f"SEC-127 RPC JSON pre-parse depth: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
