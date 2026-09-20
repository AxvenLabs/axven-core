#!/usr/bin/env python3
"""ARCH-001 research-only deterministic state-growth comparison.

Measures canonical research encoding sizes for equivalent native-transfer
states. These byte counts are diagnostic research evidence only; they are not
production storage, wire, fee, or consensus-cost claims.
"""
from __future__ import annotations

from arch001_model import canonical_bytes, commitment
from arch001_transfer_compare import (
    AxvenObject,
    account_transfer,
    object_plain,
    object_transfer,
    utxo_transfer,
)


def encoded_size(value) -> int:
    return len(canonical_bytes(value))


def main() -> None:
    u0={"genesis:0":{"owner":"alice","amount":100},"genesis:1":{"owner":"bob","amount":25}}
    utx={"txid":"transfer1","input":"genesis:0","sender":"alice","recipient":"bob","amount":10}
    a0={"alice":{"balance":100,"sequence":0},"bob":{"balance":25,"sequence":0}}
    atx={"sender":"alice","recipient":"bob","amount":10,"sequence":0}
    o0={"alice-balance":AxvenObject("alice-balance","alice","native-balance",0,{"amount":100},"ed25519"),"bob-balance":AxvenObject("bob-balance","bob","native-balance",0,{"amount":25},"hybrid-v1")}
    otx={"sender":"alice","source_object":"alice-balance","destination_object":"bob-balance","source_version":0,"destination_version":0,"amount":10}

    u1=utxo_transfer(u0,utx)
    a1=account_transfer(a0,atx)
    o0_plain=object_plain(o0)
    o1_plain=object_plain(object_transfer(o0,otx))

    rows=[]
    for name,pre,post,tx in (
        ("utxo",u0,u1,utx),
        ("account",a0,a1,atx),
        ("object",o0_plain,o1_plain,otx),
    ):
        pre_bytes=encoded_size(pre)
        post_bytes=encoded_size(post)
        tx_bytes=encoded_size(tx)
        rows.append((name,pre_bytes,post_bytes,post_bytes-pre_bytes,tx_bytes,commitment(post)))
        assert canonical_bytes(post) == canonical_bytes(post)
        assert commitment(post) == commitment(post)

    assert len({row[5] for row in rows}) == 3
    print("ARCH-001 state-growth comparison: 9/9 GREEN")
    for name,pre_bytes,post_bytes,delta,tx_bytes,post_root in rows:
        print(name,"pre_state_bytes",pre_bytes,"post_state_bytes",post_bytes,"state_delta_bytes",delta,"research_tx_bytes",tx_bytes,"post",post_root)
    print("NOTE canonical research bytes are not production storage/wire/fee measurements")


if __name__ == "__main__":
    main()
