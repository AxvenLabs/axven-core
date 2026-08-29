#!/usr/bin/env python3
"""SEC-153 persisted block/transaction canonicality contract."""

import copy
import json
import tempfile
import axven


def _write_and_load(payload):
    with tempfile.TemporaryDirectory() as td:
        store=axven.StateStore(td)
        store.path.write_text(
            json.dumps(payload,separators=(",",":")),
            encoding="utf-8",
        )
        return store.load()


def _expect(label,payload,contains):
    try:
        _write_and_load(payload)
    except ValueError as exc:
        assert contains in str(exc),(label,str(exc))
        print(f"[GREEN] {label}")
        return 1
    raise AssertionError(f"{label}: expected ValueError")


def main():
    checks=0
    wallet=axven.Wallet()
    chain=axven.Blockchain()
    chain.mine(wallet.address)
    base={
        "chain_id":axven.CHAIN_ID,
        "config_fingerprint":axven.CONFIG_FINGERPRINT,
        "blocks":[b.to_dict() for b in chain.blocks],
    }

    loaded=_write_and_load(copy.deepcopy(base))
    assert loaded.tip.hash()==chain.tip.hash()
    checks+=1
    print("[GREEN] canonical persisted block/transaction representation preserved")

    p=copy.deepcopy(base); p["blocks"][1]["extra"]=True
    checks+=_expect("unknown persisted block field rejected",p,"persisted block fields")

    p=copy.deepcopy(base); del p["blocks"][1]["nonce"]
    checks+=_expect("missing persisted block field rejected",p,"persisted block fields")

    p=copy.deepcopy(base); p["blocks"][1]["height"]=True
    checks+=_expect("boolean persisted block height rejected",p,"height must be integer")

    p=copy.deepcopy(base); p["blocks"][1]["previous_hash"]=7
    checks+=_expect("non-string persisted block hash rejected",p,"previous_hash must be string")

    p=copy.deepcopy(base); p["blocks"][1]["transactions"]={}
    checks+=_expect("non-list persisted transactions rejected",p,"transactions must be a list")

    p=copy.deepcopy(base); p["blocks"][1]["transactions"][0]["extra"]="x"
    checks+=_expect("unknown persisted transaction field rejected",p,"persisted transaction fields")

    p=copy.deepcopy(base); del p["blocks"][1]["transactions"][0]["outputs"]
    checks+=_expect("missing persisted transaction outputs rejected",p,"persisted transaction fields")

    p=copy.deepcopy(base); p["blocks"][1]["transactions"][0]["coinbase_height"]=True
    checks+=_expect("boolean persisted coinbase height rejected",p,"coinbase_height must be integer")

    p=copy.deepcopy(base); p["blocks"][1]["transactions"][0]["inputs"][0]["extra"]=1
    checks+=_expect("unknown persisted input field rejected",p,"transaction input fields")

    p=copy.deepcopy(base); p["blocks"][1]["transactions"][0]["inputs"][0]["index"]=True
    checks+=_expect("boolean persisted input index rejected",p,"input index must be integer")

    p=copy.deepcopy(base); p["blocks"][1]["transactions"][0]["inputs"][0]["signature"]=7
    checks+=_expect("non-string persisted input auth rejected",p,"signature must be string")

    p=copy.deepcopy(base); p["blocks"][1]["transactions"][0]["outputs"][0]["extra"]=1
    checks+=_expect("unknown persisted output field rejected",p,"transaction output fields")

    p=copy.deepcopy(base); p["blocks"][1]["transactions"][0]["outputs"][0]["amount"]=True
    checks+=_expect("boolean persisted output amount rejected",p,"output amount must be integer")

    p=copy.deepcopy(base); p["blocks"][1]["transactions"][0]["outputs"][0]["recipient"]=7
    checks+=_expect("non-string persisted output recipient rejected",p,"output recipient must be string")

    assert axven.CHAIN_ID=="axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks+=1
    print("[GREEN] canonical chain identity unchanged")

    assert checks==16,checks
    print("SEC-153 persisted block/transaction canonicality: 16/16 GREEN")


if __name__=="__main__":
    main()
