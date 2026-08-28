#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RPC = ROOT / "rpc.py"
SPEC = ROOT / "security_sec128_rpc_json_preparse_complexity_spec.py"
MANIFEST = ROOT / "release_manifest.json"


def replace_once(data: bytes, old: bytes, new: bytes, label: str) -> bytes:
    count = data.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return data.replace(old, new, 1)


rpc = RPC.read_bytes()
rpc = replace_once(
    rpc,
    b"MAX_RPC_JSON_NESTING_DEPTH = 32\n",
    b"MAX_RPC_JSON_NESTING_DEPTH = 32\nMAX_RPC_PARAM_NODES = 4096\nMAX_RPC_JSON_STRUCTURAL_ITEMS = 2 * MAX_RPC_PARAM_NODES\n",
    "RPC structural complexity constants",
)

old_helper = b'''def _preflight_json_nesting(raw):
    """Bound raw JSON container nesting before invoking Python's parser."""
    stack = []
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # quote
                in_string = False
            continue

        if byte == 0x22:
            in_string = True
            continue
        if byte in (0x7B, 0x5B):  # { [
            stack.append(byte)
            if len(stack) > MAX_RPC_JSON_NESTING_DEPTH:
                raise RPCError("JSON nesting depth exceeded")
            continue
        if byte in (0x7D, 0x5D):  # } ]
            expected = 0x7B if byte == 0x7D else 0x5B
            if stack and stack[-1] == expected:
                stack.pop()
'''
new_helper = b'''def _preflight_json_nesting(raw):
    """Bound raw JSON nesting and structural fan-out before parser allocation."""
    stack = []
    structural_items = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # quote
                in_string = False
            continue

        if byte == 0x22:
            in_string = True
            continue
        if byte in (0x7B, 0x5B):  # { [
            structural_items += 1
            if structural_items > MAX_RPC_JSON_STRUCTURAL_ITEMS:
                raise RPCError("JSON structural complexity exceeded")
            stack.append(byte)
            if len(stack) > MAX_RPC_JSON_NESTING_DEPTH:
                raise RPCError("JSON nesting depth exceeded")
            continue
        if byte == 0x2C and stack:  # comma between container members/items
            structural_items += 1
            if structural_items > MAX_RPC_JSON_STRUCTURAL_ITEMS:
                raise RPCError("JSON structural complexity exceeded")
            continue
        if byte in (0x7D, 0x5D):  # } ]
            expected = 0x7B if byte == 0x7D else 0x5B
            if stack and stack[-1] == expected:
                stack.pop()
'''
rpc = replace_once(rpc, old_helper, new_helper, "RPC raw preflight")
rpc = replace_once(
    rpc,
    b"        budget = [4096]\n",
    b"        budget = [MAX_RPC_PARAM_NODES]\n",
    "validate-param default budget",
)
rpc = replace_once(
    rpc,
    b"            budget = [4096]\n",
    b"            budget = [MAX_RPC_PARAM_NODES]\n",
    "dispatcher param budget",
)
RPC.write_bytes(rpc)

spec = r'''#!/usr/bin/env python3
"""SEC-128 bound shallow RPC JSON fan-out before json.loads."""

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
        b'{"method":"get_status","params":{"payload":['
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

    canonical_max = list_request(4095)
    rpc._preflight_json_nesting(canonical_max)
    parsed = json.loads(canonical_max)
    result = rpc.RPCDispatcher(Core()).call(parsed["method"], parsed["params"])
    green(
        "existing exact 4096-node semantic RPC boundary remains admissible",
        result["height"] == 7,
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
        b'{"method":"get_status","params":{"payload":['
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
            "method": "get_status",
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

        healthy_status, healthy_body = post_raw(server.address, canonical_max)
        healthy = json.loads(healthy_body)
        green(
            "maximum canonical semantic payload remains available through production HTTP",
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

    print(f"SEC-128 RPC JSON pre-parse complexity: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
'''
SPEC.write_bytes(spec.encode("utf-8"))

manifest_raw = MANIFEST.read_bytes()
manifest = json.loads(manifest_raw)
canonical_before = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
if canonical_before != manifest_raw:
    raise RuntimeError("release manifest serialization is not canonical; refusing broad rewrite")

for path in (RPC, SPEC):
    raw = path.read_bytes()
    manifest["files"][path.name] = {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }

MANIFEST.write_bytes((json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))

print("SEC-128 staged")
for path in (RPC, SPEC):
    raw = path.read_bytes()
    print(path.name, len(raw), hashlib.sha256(raw).hexdigest())
