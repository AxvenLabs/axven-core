#!/usr/bin/env python3
"""SEC-181: RPC clients require one exact success/error response envelope."""

import io
import json

import axven
import axven_cli


def _read_obj(value):
    raw=json.dumps(value,separators=(",", ":")).encode("utf-8")
    return axven_cli.read_rpc_json_response(io.BytesIO(raw))


def _reject_obj(value):
    try:
        _read_obj(value)
    except axven_cli.RPCClientError:
        return
    raise AssertionError(f"RPC response unexpectedly accepted: {value!r}")


def _reject_raw(raw):
    try:
        axven_cli.read_rpc_json_response(io.BytesIO(raw))
    except axven_cli.RPCClientError:
        return
    raise AssertionError(f"raw RPC response unexpectedly accepted: {raw!r}")


def main():
    success={"ok":True,"result":{"height":7,"items":[1,2,3]}}
    assert _read_obj(success)==success
    print("[GREEN] canonical success envelope accepted")

    null_success={"ok":True,"result":None}
    assert _read_obj(null_success)==null_success
    print("[GREEN] arbitrary JSON result payload preserved")

    failure={"ok":False,"error":"RPCError: rejected"}
    assert _read_obj(failure)==failure
    print("[GREEN] canonical error envelope accepted")

    for value in ([], [1], "text", 1, True, None):
        _reject_obj(value)
    print("[GREEN] non-object envelopes rejected")

    for value in ({"result":1}, {"error":"x"}, {}):
        _reject_obj(value)
    print("[GREEN] missing ok field rejected")

    for alias in (0,1,"true","false",None,[],{}):
        _reject_obj({"ok":alias,"result":None})
    print("[GREEN] non-boolean ok aliases rejected")

    _reject_obj({"ok":True})
    print("[GREEN] success missing result rejected")

    _reject_obj({"ok":True,"result":1,"error":"contradiction"})
    _reject_obj({"ok":True,"result":1,"extra":2})
    print("[GREEN] success contradiction and extra fields rejected")

    _reject_obj({"ok":False})
    print("[GREEN] error missing error field rejected")

    for error in (None,0,False,[],{},""):
        _reject_obj({"ok":False,"error":error})
    print("[GREEN] error payload requires non-empty string")

    _reject_obj({"ok":False,"error":"x","result":1})
    _reject_obj({"ok":False,"error":"x","extra":2})
    print("[GREEN] error contradiction and extra fields rejected")

    _reject_raw(b'{"ok":true,"ok":false,"error":"x"}')
    print("[GREEN] SEC-180 duplicate-key rejection preserved")

    assert axven.CHAIN_ID=="axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    print("[GREEN] canonical chain identity unchanged")

    print("SEC-181 RPC client response envelope canonicality: 13/13 GREEN")


if __name__=="__main__":
    main()
