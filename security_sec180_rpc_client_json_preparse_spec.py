#!/usr/bin/env python3
"""SEC-180: RPC client responses are bounded before JSON parser allocation."""
from __future__ import annotations

import inspect

import axven
import axven_cli
import axven_console
import canonical_ops


class FakeStream:
    def __init__(self,payload):
        self.payload=payload
        self.read_sizes=[]
    def read(self,n=-1):
        self.read_sizes.append(n)
        return self.payload if n<0 else self.payload[:n]


def rejected(payload,expected=None):
    try:
        axven_cli.read_rpc_json_response(FakeStream(payload))
    except axven_cli.RPCClientError as exc:
        return expected is None or str(exc)==expected
    return False


def main():
    checks=[]
    def green(name,cond):
        assert cond,name
        checks.append(name)
        print(f"[GREEN] {name}")

    green(
        "finite response JSON limits",
        type(axven_cli.MAX_RPC_RESPONSE_JSON_NESTING_DEPTH) is int
        and 8 <= axven_cli.MAX_RPC_RESPONSE_JSON_NESTING_DEPTH <= 64
        and type(axven_cli.MAX_RPC_RESPONSE_JSON_STRUCTURAL_ITEMS) is int
        and 8192 <= axven_cli.MAX_RPC_RESPONSE_JSON_STRUCTURAL_ITEMS <= 2*1024*1024,
    )

    healthy=FakeStream(b'{"ok":true,"result":{"height":0}}')
    parsed=axven_cli.read_rpc_json_response(healthy)
    green("canonical bounded response preserved",parsed["ok"] is True)

    original_depth=axven_cli.MAX_RPC_RESPONSE_JSON_NESTING_DEPTH
    original_items=axven_cli.MAX_RPC_RESPONSE_JSON_STRUCTURAL_ITEMS
    try:
        axven_cli.MAX_RPC_RESPONSE_JSON_NESTING_DEPTH=3
        green(
            "exact nesting boundary accepted",
            axven_cli.read_rpc_json_response(FakeStream(b'{"a":{"b":[]}}'))["a"]["b"]==[],
        )

        loads_called=[]
        old_loads=axven_cli.json.loads
        try:
            axven_cli.json.loads=lambda *a,**k: loads_called.append(True) or old_loads(*a,**k)
            green(
                "over-depth response rejected before parser",
                rejected(b'{"a":{"b":[[]]}}',"RPC response JSON nesting too deep")
                and loads_called==[],
            )
        finally:
            axven_cli.json.loads=old_loads

        green(
            "quoted structural bytes ignored",
            axven_cli.read_rpc_json_response(
                FakeStream(b'{"text":"[[[[{{{{,,,,}}}}]]]]"}')
            )["text"].startswith("[[[["),
        )

        axven_cli.MAX_RPC_RESPONSE_JSON_STRUCTURAL_ITEMS=4
        green(
            "exact structural boundary accepted",
            axven_cli.read_rpc_json_response(FakeStream(b'{"x":[1,2,3]}'))["x"]==[1,2,3],
        )
        loads_called=[]
        old_loads=axven_cli.json.loads
        try:
            axven_cli.json.loads=lambda *a,**k: loads_called.append(True) or old_loads(*a,**k)
            green(
                "over-complex response rejected before parser",
                rejected(b'{"x":[1,2,3,4]}',"RPC response JSON too complex")
                and loads_called==[],
            )
        finally:
            axven_cli.json.loads=old_loads
    finally:
        axven_cli.MAX_RPC_RESPONSE_JSON_NESTING_DEPTH=original_depth
        axven_cli.MAX_RPC_RESPONSE_JSON_STRUCTURAL_ITEMS=original_items

    green(
        "duplicate top-level key rejected",
        rejected(b'{"ok":true,"ok":false}',"duplicate RPC response JSON key"),
    )
    green(
        "duplicate nested key rejected",
        rejected(b'{"ok":true,"result":{"x":1,"x":2}}',"duplicate RPC response JSON key"),
    )
    green("invalid UTF-8 rejected",rejected(b'{"x":"\xff"}'))
    green("malformed JSON rejected",rejected(b'{"x":'))
    green(
        "oversized JSON integer fails closed",
        rejected(b'{"n":'+(b'9'*5000)+b'}'),
    )
    green(
        "top-level object contract preserved",
        rejected(b'[]',"RPC response must be object"),
    )

    reader_src=inspect.getsource(axven_cli.read_rpc_json_response)
    green(
        "preflight precedes JSON parser",
        reader_src.index("_preflight_rpc_response_json(raw)") < reader_src.index("json.loads"),
    )
    green(
        "strict UTF-8 decode precedes JSON parser",
        reader_src.index('raw.decode("utf-8")') < reader_src.index("json.loads"),
    )
    green(
        "SEC-164 byte budget preserved",
        "MAX_RPC_RESPONSE_BYTES+1" in reader_src and axven_cli.MAX_RPC_RESPONSE_BYTES==16*1024*1024,
    )
    green(
        "operator and console share hardened reader path",
        axven_console.call is axven_cli.call
        and "read_rpc_json_response" in inspect.getsource(canonical_ops.rpc),
    )
    green(
        "canonical chain identity unchanged",
        axven.CHAIN_ID=="axven-devnet-2"
        and axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae",
    )
    print(f"SEC-180 RPC client JSON preparse: {len(checks)}/{len(checks)} GREEN")


if __name__=="__main__":
    main()
