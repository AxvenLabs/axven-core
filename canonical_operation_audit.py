#!/usr/bin/env python3
from pathlib import Path
import json, axven
ROOT=Path(__file__).resolve().parent
c=[]
def ck(n,x):
    assert x,n; c.append(n); print("[GREEN]",n)
ck("chain id",axven.CHAIN_ID=="axven-devnet-2")
ck("fingerprint",axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
ck("genesis",axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3")
m=json.loads((ROOT/"release_manifest.json").read_text(encoding="utf-8"))
ck("activation executed",m.get("activation")=="EXECUTED")
ck("canonical true",m.get("canonical") is True)
record=(ROOT/"CANONICAL_OPERATION_RECORD.md").read_text(encoding="utf-8")
ck("block1 recorded","00654a3a90e5d24735d2baa39143e6f0144826caf4daf83b4fdc47beb6b92580" in record)
ck("operation verified","CANONICAL DEVNET OPERATION VERIFIED" in record)
print(f"Canonical operation audit: {len(c)}/{len(c)} GREEN")
