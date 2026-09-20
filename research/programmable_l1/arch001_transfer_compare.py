#!/usr/bin/env python3
"""ARCH-001 research-only native AXVEN transfer comparison.

No production consensus imports or routing. The three models use equivalent
Alice=100, Bob=25, transfer=10 workloads and deterministic JSON commitments.
"""
from __future__ import annotations
from copy import deepcopy
from arch001_model import AxvenObject, ResearchTransitionError, commitment


def _positive(amount: int) -> None:
    if type(amount) is not int or amount <= 0:
        raise ResearchTransitionError("amount must be positive int")


def utxo_transfer(state, tx):
    _positive(tx["amount"])
    outpoint = tx["input"]
    if outpoint not in state:
        raise ResearchTransitionError("missing/spent input")
    coin = state[outpoint]
    if coin["owner"] != tx["sender"] or coin["amount"] < tx["amount"]:
        raise ResearchTransitionError("unauthorized/insufficient input")
    nxt = deepcopy(state); del nxt[outpoint]
    nxt[tx["txid"]+":0"]={"owner":tx["recipient"],"amount":tx["amount"]}
    change=coin["amount"]-tx["amount"]
    if change: nxt[tx["txid"]+":1"]={"owner":tx["sender"],"amount":change}
    return nxt


def account_transfer(state, tx):
    _positive(tx["amount"])
    nxt=deepcopy(state); src=nxt[tx["sender"]]; dst=nxt[tx["recipient"]]
    if tx["sequence"] != src["sequence"]: raise ResearchTransitionError("stale account sequence")
    if src["balance"] < tx["amount"]: raise ResearchTransitionError("insufficient balance")
    src["balance"]-=tx["amount"]; src["sequence"]+=1; dst["balance"]+=tx["amount"]
    return nxt


def object_transfer(state, tx):
    _positive(tx["amount"])
    nxt=deepcopy(state); src=nxt[tx["source_object"]]; dst=nxt[tx["destination_object"]]
    if src.owner_or_authority != tx["sender"]: raise ResearchTransitionError("unauthorized object")
    if src.version != tx["source_version"] or dst.version != tx["destination_version"]:
        raise ResearchTransitionError("stale object version")
    if src.data["amount"] < tx["amount"]: raise ResearchTransitionError("insufficient object balance")
    nxt[tx["source_object"]]=AxvenObject(src.object_id,src.owner_or_authority,src.object_type,src.version+1,{"amount":src.data["amount"]-tx["amount"]},src.authorization_policy)
    nxt[tx["destination_object"]]=AxvenObject(dst.object_id,dst.owner_or_authority,dst.object_type,dst.version+1,{"amount":dst.data["amount"]+tx["amount"]},dst.authorization_policy)
    return nxt


def object_plain(state): return {k:v.canonical() for k,v in sorted(state.items())}

def rejected(fn, state, tx):
    try: fn(state, tx)
    except ResearchTransitionError: return True
    return False


def main():
    u0={"genesis:0":{"owner":"alice","amount":100},"genesis:1":{"owner":"bob","amount":25}}
    utx={"txid":"transfer1","input":"genesis:0","sender":"alice","recipient":"bob","amount":10}
    a0={"alice":{"balance":100,"sequence":0},"bob":{"balance":25,"sequence":0}}
    atx={"sender":"alice","recipient":"bob","amount":10,"sequence":0}
    o0={"alice-balance":AxvenObject("alice-balance","alice","native-balance",0,{"amount":100},"ed25519"),"bob-balance":AxvenObject("bob-balance","bob","native-balance",0,{"amount":25},"hybrid-v1")}
    otx={"sender":"alice","source_object":"alice-balance","destination_object":"bob-balance","source_version":0,"destination_version":0,"amount":10}

    u1=utxo_transfer(u0,utx); a1=account_transfer(a0,atx); o1=object_transfer(o0,otx)
    assert sum(x["amount"] for x in u1.values()) == 125
    assert sum(x["balance"] for x in a1.values()) == 125
    assert sum(x.data["amount"] for x in o1.values()) == 125
    assert commitment(utxo_transfer(u0,utx)) == commitment(u1)
    assert commitment(account_transfer(a0,atx)) == commitment(a1)
    assert commitment(object_plain(object_transfer(o0,otx))) == commitment(object_plain(o1))
    assert rejected(utxo_transfer,u1,utx)  # spent outpoint replay
    assert rejected(account_transfer,a1,atx)  # stale sequence replay
    assert rejected(object_transfer,o1,otx)  # stale versions replay

    rows=[]
    for name,pre,post,tx in [("utxo",u0,u1,utx),("account",a0,a1,atx),("object",object_plain(o0),object_plain(o1),otx)]:
        rows.append((name,len(str(tx)),commitment(pre),commitment(post)))
    print("ARCH-001 native transfer comparison: 9/9 GREEN")
    for name,txchars,pre,post in rows: print(name,"research_tx_chars",txchars,"pre",pre,"post",post)

if __name__ == "__main__": main()
