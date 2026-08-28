#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RPC = ROOT / "rpc.py"
SPEC = ROOT / "security_sec127_rpc_json_preparse_depth_spec.py"
MANIFEST = ROOT / "release_manifest.json"


def replace_once(data: bytes, old: bytes, new: bytes, label: str) -> bytes:
    count = data.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return data.replace(old, new, 1)


rpc = RPC.read_bytes()
rpc = replace_once(
    rpc,
    b"MAX_RPC_REQUEST_BYTES = 2 * 1024 * 1024\n",
    b"MAX_RPC_REQUEST_BYTES = 2 * 1024 * 1024\nMAX_RPC_JSON_NESTING_DEPTH = 32\n",
    "RPC nesting constant",
)

helper_anchor = b'''def _reject_duplicate_json_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise RPCError(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def _validate_param_depth'''
helper_replacement = b'''def _reject_duplicate_json_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise RPCError(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def _preflight_json_nesting(raw):
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


def _validate_param_depth'''
rpc = replace_once(rpc, helper_anchor, helper_replacement, "RPC preflight helper")

parse_anchor = b'''                self._cancel_request_deadline()
                req = json.loads(raw_request, object_pairs_hook=_reject_duplicate_json_keys)
'''
parse_replacement = b'''                self._cancel_request_deadline()
                _preflight_json_nesting(raw_request)
                req = json.loads(raw_request, object_pairs_hook=_reject_duplicate_json_keys)
'''
rpc = replace_once(rpc, parse_anchor, parse_replacement, "RPC parser wiring")
RPC.write_bytes(rpc)

spec = r'''#!/usr/bin/env python3
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
    shallow_ok = dispatcher.call("get_status", {"x": nested_value(16)})["height"] == 7
    try:
        dispatcher.call("get_status", {"x": nested_value(17)})
        parsed_depth_rejected = False
    except rpc.RPCError as exc:
        parsed_depth_rejected = "nesting too deep" in str(exc)
    green(
        "existing parsed parameter depth contract remains independently enforced",
        shallow_ok and parsed_depth_rejected,
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

print("SEC-127 staged")
for path in (RPC, SPEC):
    raw = path.read_bytes()
    print(path.name, len(raw), hashlib.sha256(raw).hexdigest())
