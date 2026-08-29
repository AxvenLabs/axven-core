#!/usr/bin/env python3
"""SEC-130 bound shallow RPC JSON fan-out before json.loads."""

import http.client
import inspect
import json

import rpc


class Core:
    def status(self):
        return {"height": 7, "tip_hash": "0" * 64}


def post_raw(address, raw):
    conn = http.client.HTTPConnection(address[0], address[1], timeout=3)
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


def list_request(count):
    return (
        b'{"method":"__sec130_unknown_method__","params":{"payload":['
        + b','.join([b'0'] * count)
        + b']}}'
    )


def main():
    checks = []

    def green(name, condition):
        assert condition, name
        checks.append(name)
        print("[GREEN]", name)

    green(
        "RPC parsed and raw structural budgets are pinned with explicit headroom",
        rpc.MAX_RPC_PARAM_NODES == 4096
        and rpc.MAX_RPC_JSON_STRUCTURAL_ITEMS == 8192
        and rpc.MAX_RPC_JSON_STRUCTURAL_ITEMS == 2 * rpc.MAX_RPC_PARAM_NODES,
    )

    # SEC-130 owns semantic/raw complexity limits. SEC-171 now owns exact
    # production-method vocabularies, so use an unknown method to prove the
    # exact semantic boundary reaches the later method gate without relying
    # on a production method silently ignoring a synthetic payload field.
    canonical_max = list_request(4095)
    rpc._preflight_json_nesting(canonical_max)
    parsed = json.loads(canonical_max)
    try:
        rpc.RPCDispatcher(Core()).call(parsed["method"], parsed["params"])
        semantic_boundary_reached = False
    except rpc.RPCError as exc:
        semantic_boundary_reached = str(exc) == "unknown method"
    green(
        "existing exact 4096-node semantic RPC boundary reaches method gate",
        semantic_boundary_reached,
    )

    semantic_over = list_request(4096)
    rpc._preflight_json_nesting(semantic_over)
    parsed_over = json.loads(semantic_over)
    try:
        rpc.RPCDispatcher(Core()).call(parsed_over["method"], parsed_over["params"])
        semantic_rejected = False
    except rpc.RPCError as exc:
        semantic_rejected = "params too complex" in str(exc)
    green(
        "existing semantic complexity layer still rejects one node over its boundary",
        semantic_rejected,
    )

    over_raw = list_request(rpc.MAX_RPC_JSON_STRUCTURAL_ITEMS + 1)
    green(
        "over-complex shallow fixture remains well below the RPC byte and depth caps",
        len(over_raw) < rpc.MAX_RPC_REQUEST_BYTES
        and over_raw.count(b'[') == 1,
    )
    try:
        rpc._preflight_json_nesting(over_raw)
        raw_rejected = False
    except rpc.RPCError as exc:
        raw_rejected = "structural complexity exceeded" in str(exc)
    green("shallow structural fan-out is rejected before parsing", raw_rejected)

    empty_container_fanout = (
        b'{"method":"__sec130_unknown_method__","params":{"payload":['
        + b','.join([b'{}'] * (rpc.MAX_RPC_JSON_STRUCTURAL_ITEMS + 1))
        + b']}}'
    )
    try:
        rpc._preflight_json_nesting(empty_container_fanout)
        container_rejected = False
    except rpc.RPCError as exc:
        container_rejected = "structural complexity exceeded" in str(exc)
    green("empty-container allocation fan-out is independently bounded", container_rejected)

    string_noise = json.dumps(
        {
            "method": "__sec130_unknown_method__",
            "params": {"text": ",{}[]" * (rpc.MAX_RPC_JSON_STRUCTURAL_ITEMS + 32)},
        },
        separators=(",", ":"),
    ).encode("utf-8")
    rpc._preflight_json_nesting(string_noise)
    green("structural-looking bytes inside strings consume no raw fan-out budget", True)

    server = rpc.RPCServer(Core()).start()
    try:
        parser_calls = []
        original_loads = rpc.json.loads

        def trap_loads(*args, **kwargs):
            parser_calls.append(1)
            raise AssertionError("json.loads must not run for over-complex RPC input")

        rpc.json.loads = trap_loads
        try:
            status, _ = post_raw(server.address, over_raw)
        finally:
            rpc.json.loads = original_loads
        green(
            "production HTTP path rejects structural fan-out before json.loads",
            status == 400 and not parser_calls,
        )

        parser_calls = []

        def counting_loads(*args, **kwargs):
            parser_calls.append(1)
            return original_loads(*args, **kwargs)

        rpc.json.loads = counting_loads
        try:
            semantic_status, _ = post_raw(server.address, semantic_over)
        finally:
            rpc.json.loads = original_loads
        green(
            "semantic-only overflow still reaches parser then fails at canonical node budget",
            semantic_status == 400 and len(parser_calls) == 1,
        )

        parser_calls = []
        rpc.json.loads = counting_loads
        try:
            boundary_status, boundary_body = post_raw(server.address, canonical_max)
        finally:
            rpc.json.loads = original_loads
        boundary = json.loads(boundary_body)
        green(
            "maximum semantic payload reaches method gate through production HTTP",
            boundary_status == 400
            and len(parser_calls) == 1
            and boundary.get("ok") is False
            and "unknown method" in boundary.get("error", ""),
        )

        healthy_raw = json.dumps(
            {"method": "get_status", "params": {}},
            separators=(",", ":"),
        ).encode("utf-8")
        healthy_status, healthy_body = post_raw(server.address, healthy_raw)
        healthy = json.loads(healthy_body)
        green(
            "healthy canonical production RPC remains available",
            healthy_status == 200
            and healthy.get("ok") is True
            and healthy.get("result", {}).get("height") == 7,
        )
    finally:
        server.stop()

    src = inspect.getsource(rpc._preflight_json_nesting)
    green(
        "raw complexity accounting is quote-aware and enforced in the SEC-127 preflight",
        "structural_items" in src
        and "MAX_RPC_JSON_STRUCTURAL_ITEMS" in src
        and "byte == 0x2C and stack" in src,
    )

    validate_src = inspect.getsource(rpc._validate_param_depth)
    dispatch_src = inspect.getsource(rpc.RPCDispatcher.call)
    green(
        "semantic node budget is single-sourced instead of duplicated magic literals",
        "MAX_RPC_PARAM_NODES" in validate_src
        and "MAX_RPC_PARAM_NODES" in dispatch_src
        and "[4096]" not in validate_src
        and "[4096]" not in dispatch_src,
    )

    handler_src = inspect.getsource(rpc._handler)
    green(
        "pre-parse structural gate remains before json.loads in production wiring",
        handler_src.index("_preflight_json_nesting(raw_request)")
        < handler_src.index("json.loads(raw_request"),
    )

    print(f"SEC-130 RPC JSON pre-parse complexity: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
