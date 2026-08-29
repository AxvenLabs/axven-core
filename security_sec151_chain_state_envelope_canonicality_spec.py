#!/usr/bin/env python3
"""SEC-151 persisted chain-state envelope canonicality contract."""

import json
import tempfile
import axven


def _write(store,payload):
    store.path.write_text(
        json.dumps(payload,separators=(",",":")),
        encoding="utf-8",
    )


def _expect(label,payload,contains):
    with tempfile.TemporaryDirectory() as td:
        store=axven.StateStore(td)
        _write(store,payload)
        try:
            store.load()
        except ValueError as exc:
            assert contains in str(exc),(label,str(exc))
            print(f"[GREEN] {label}")
            return 1
        raise AssertionError(f"{label}: expected ValueError")


def _canonical_payload():
    chain=axven.Blockchain()
    return {
        "chain_id":axven.CHAIN_ID,
        "config_fingerprint":axven.CONFIG_FINGERPRINT,
        "blocks":[b.to_dict() for b in chain.blocks],
    }


def main():
    checks=0

    with tempfile.TemporaryDirectory() as td:
        store=axven.StateStore(td)
        chain=axven.Blockchain()
        store.persist(chain)
        loaded=store.load()
        assert loaded.tip.hash()==chain.tip.hash()
        checks+=1
        print("[GREEN] canonical persisted envelope preserved")

    p=_canonical_payload(); p["extra"]=True
    checks+=_expect("unknown top-level field rejected",p,"envelope fields")

    p=_canonical_payload(); del p["chain_id"]
    checks+=_expect("missing chain_id rejected",p,"envelope fields")

    p=_canonical_payload(); del p["config_fingerprint"]
    checks+=_expect("missing config fingerprint rejected",p,"envelope fields")

    p=_canonical_payload(); del p["blocks"]
    checks+=_expect("missing blocks rejected",p,"envelope fields")

    p=_canonical_payload(); p["chain_id"]=True
    checks+=_expect("non-string chain_id rejected",p,"chain_id must be string")

    p=_canonical_payload(); p["config_fingerprint"]=False
    checks+=_expect("non-string config fingerprint rejected",p,"fingerprint must be string")

    p=_canonical_payload(); p["blocks"]={}
    checks+=_expect("non-list blocks rejected",p,"blocks must be a list")

    p=_canonical_payload(); p["blocks"]=[p["blocks"][0],"not-a-block"]
    checks+=_expect("non-object block entry rejected before Block.from_dict",p,"block entries must be objects")

    assert axven.CHAIN_ID=="axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks+=1
    print("[GREEN] canonical chain identity unchanged")

    assert checks==10,checks
    print("SEC-151 chain-state envelope canonicality: 10/10 GREEN")


if __name__=="__main__":
    main()
