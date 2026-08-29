#!/usr/bin/env python3
"""SEC-171 RPC method-specific parameter canonicality contract."""

import axven
import rpc


class FakeCore:
    def __init__(self):
        self.calls=[]

    def status(self):
        self.calls.append(("status",))
        return {"ok":True}

    def recent_blocks(self,limit):
        self.calls.append(("recent_blocks",limit))
        return []

    def get_block(self,ident):
        self.calls.append(("get_block",ident))
        return {"height":ident}

    def send(self,input_scheme,recipient,amount,fee):
        self.calls.append(("send",input_scheme,recipient,amount,fee))
        return {"txid":"0"*64}


def expect_error(dispatcher,method,params,message):
    try:
        dispatcher.call(method,params)
    except rpc.RPCError as exc:
        assert str(exc)==message,(method,params,str(exc),message)
        return
    raise AssertionError(f"RPC accepted non-canonical params: {method} {params!r}")


def main():
    checks=[]
    def green(name,condition):
        assert condition,name
        checks.append(name)
        print(f"[GREEN] {name}")

    expected_methods={
        "get_status","get_overview","get_explorer_summary","get_recent_blocks",
        "get_block","get_transaction","get_mempool","get_chain_config",
        "get_addresses","get_balance","get_wallet_status","list_unspent",
        "get_peers","get_peer_health","add_peer","sync_peers","remove_peer",
        "mine","send","start_p2p","stop","sync_peer",
    }
    green(
        "RPC canonical schema covers every production dispatcher method",
        set(rpc._RPC_METHOD_PARAM_SCHEMA)==expected_methods,
    )

    core=FakeCore()
    dispatcher=rpc.RPCDispatcher(core)
    green(
        "zero-param method accepts absent params",
        dispatcher.call("get_status",None)=={"ok":True},
    )
    before=len(core.calls)
    expect_error(dispatcher,"get_status",{"extra":1},"unknown RPC param: extra")
    green(
        "zero-param method rejects ignored aliases before core dispatch",
        len(core.calls)==before,
    )

    green(
        "documented optional param remains accepted",
        dispatcher.call("get_recent_blocks",{"limit":7})==[]
        and core.calls[-1]==("recent_blocks",7),
    )
    before=len(core.calls)
    expect_error(dispatcher,"get_recent_blocks",{"limit":7,"junk":1},"unknown RPC param: junk")
    green("optional-param method rejects extras before core dispatch",len(core.calls)==before)

    before=len(core.calls)
    expect_error(dispatcher,"get_block",{},"missing RPC param: id")
    green("required param is enforced before core dispatch",len(core.calls)==before)
    green(
        "canonical required param reaches core",
        dispatcher.call("get_block",{"id":0})=={"height":0}
        and core.calls[-1]==("get_block",0),
    )

    send_params={
        "input_scheme":"N","recipient":"N:"+"0"*64,"amount":1,"fee":0,
    }
    green(
        "mutating send accepts only its complete canonical vocabulary",
        dispatcher.call("send",send_params)=={"txid":"0"*64}
        and core.calls[-1][0]=="send",
    )
    before=len(core.calls)
    expect_error(
        dispatcher,"send",
        {**send_params,"memo":"ignored"},
        "unknown RPC param: memo",
    )
    green("mutating send rejects ignored extra fields before core work",len(core.calls)==before)
    incomplete=dict(send_params); incomplete.pop("fee")
    expect_error(dispatcher,"send",incomplete,"missing RPC param: fee")
    green("mutating send rejects missing required fields",len(core.calls)==before)

    expect_error(dispatcher,"__sec171_unknown__",{},"unknown method")
    green("unknown-method behavior remains fail-closed",True)

    green(
        "RPC parameter canonicality leaves chain identity unchanged",
        axven.CHAIN_ID=="axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        =="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        =="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )
    print(f"SEC-171 RPC method param canonicality: {len(checks)}/{len(checks)} GREEN")


if __name__=="__main__":
    main()
