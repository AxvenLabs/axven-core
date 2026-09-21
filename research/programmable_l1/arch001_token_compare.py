#!/usr/bin/env python3
"""ARCH-001 research-only issued-token create/transfer comparison.

No production consensus imports or routing. Each candidate models the same
issuer Alice creating TEST with supply 1000 and transferring 125 to Bob.
"""
from __future__ import annotations
from copy import deepcopy
from arch001_model import AxvenObject, ResearchTransitionError, canonical_bytes, commitment


def rejected(fn, state, tx):
    try: fn(state, tx)
    except ResearchTransitionError: return True
    return False


def utxo_transfer(state, tx):
    outpoint=tx["input"]
    if outpoint not in state: raise ResearchTransitionError("missing/spent token input")
    coin=state[outpoint]
    if coin["asset"] != tx["asset"] or coin["owner"] != tx["sender"] or coin["amount"] < tx["amount"]:
        raise ResearchTransitionError("token input mismatch")
    nxt=deepcopy(state); del nxt[outpoint]
    nxt[tx["txid"]+":0"]={"asset":tx["asset"],"owner":tx["recipient"],"amount":tx["amount"]}
    change=coin["amount"]-tx["amount"]
    if change: nxt[tx["txid"]+":1"]={"asset":tx["asset"],"owner":tx["sender"],"amount":change}
    return nxt


def account_transfer(state, tx):
    nxt=deepcopy(state); src=nxt[tx["sender"]]; dst=nxt[tx["recipient"]]
    if tx["sequence"] != src["sequence"]: raise ResearchTransitionError("stale account sequence")
    if src["tokens"].get(tx["asset"],0) < tx["amount"]: raise ResearchTransitionError("insufficient token balance")
    src["tokens"][tx["asset"]]-=tx["amount"]; src["sequence"]+=1
    dst["tokens"][tx["asset"]]=dst["tokens"].get(tx["asset"],0)+tx["amount"]
    return nxt


def object_transfer(state, tx):
    nxt=deepcopy(state); src=nxt[tx["source_object"]]; dst=nxt[tx["destination_object"]]
    if src.owner_or_authority != tx["sender"]: raise ResearchTransitionError("unauthorized token object")
    if src.version != tx["source_version"] or dst.version != tx["destination_version"]:
        raise ResearchTransitionError("stale token object version")
    if src.data["asset"] != tx["asset"] or dst.data["asset"] != tx["asset"] or src.data["amount"] < tx["amount"]:
        raise ResearchTransitionError("token object mismatch")
    nxt[src.object_id]=AxvenObject(src.object_id,src.owner_or_authority,src.object_type,src.version+1,{"asset":tx["asset"],"amount":src.data["amount"]-tx["amount"]},src.authorization_policy)
    nxt[dst.object_id]=AxvenObject(dst.object_id,dst.owner_or_authority,dst.object_type,dst.version+1,{"asset":tx["asset"],"amount":dst.data["amount"]+tx["amount"]},dst.authorization_policy)
    return nxt


def plain(state): return {k:v.canonical() for k,v in sorted(state.items())}


def main():
    asset="TEST"; supply=1000; amount=125
    # Creation is represented explicitly in each pre-state; issuance policy is
    # deliberately research-only and is not mapped to AXVEN monetary semantics.
    u0={"issue:0":{"asset":asset,"owner":"alice","amount":supply}}
    utx={"txid":"token-transfer-1","input":"issue:0","asset":asset,"sender":"alice","recipient":"bob","amount":amount}
    a0={"alice":{"sequence":0,"tokens":{asset:supply}},"bob":{"sequence":0,"tokens":{asset:0}}}
    atx={"asset":asset,"sender":"alice","recipient":"bob","amount":amount,"sequence":0}
    o0={"alice-test":AxvenObject("alice-test","alice","token-balance",0,{"asset":asset,"amount":supply},"ed25519"),"bob-test":AxvenObject("bob-test","bob","token-balance",0,{"asset":asset,"amount":0},"ed25519")}
    otx={"asset":asset,"sender":"alice","source_object":"alice-test","destination_object":"bob-test","source_version":0,"destination_version":0,"amount":amount}

    u1=utxo_transfer(u0,utx); a1=account_transfer(a0,atx); o1=object_transfer(o0,otx)
    assert sum(x["amount"] for x in u1.values() if x["asset"]==asset) == supply
    assert sum(x["tokens"].get(asset,0) for x in a1.values()) == supply
    assert sum(x.data["amount"] for x in o1.values() if x.data["asset"]==asset) == supply
    assert commitment(utxo_transfer(u0,utx)) == commitment(u1)
    assert commitment(account_transfer(a0,atx)) == commitment(a1)
    assert commitment(plain(object_transfer(o0,otx))) == commitment(plain(o1))
    assert rejected(utxo_transfer,u1,utx)
    assert rejected(account_transfer,a1,atx)
    assert rejected(object_transfer,o1,otx)

    print("ARCH-001 token workload comparison: 9/9 GREEN")
    for name,pre,post,tx in (("utxo",u0,u1,utx),("account",a0,a1,atx),("object",plain(o0),plain(o1),otx)):
        print(name,"canonical_tx_bytes",len(canonical_bytes(tx)),"pre",commitment(pre),"post",commitment(post))

if __name__ == "__main__": main()
