#!/usr/bin/env python3
from pathlib import Path
import json, axven
ROOT=Path(__file__).resolve().parent
c=[]
def ck(n,x):
    assert x,n; c.append(n); print("[GREEN]",n)
ck("chain id canonical",axven.CHAIN_ID=="axven-devnet-2")
ck("fingerprint canonical",axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
ck("genesis canonical",axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3")
m=json.loads((ROOT/"release_manifest.json").read_text())
ck("CD-003 executed",m.get("activation")=="EXECUTED" and m.get("activation_decision")=="CD-003")
ck("manifest canonical",m.get("canonical") is True)
ck("manifest chain pin",m.get("chain_id")=="axven-devnet-2")
ck("manifest fingerprint pin",m.get("config_fingerprint")=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
ck("manifest genesis pin",m.get("genesis_hash")=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3")
record=(ROOT/"CD-003_ACTIVATION.md").read_text(encoding="utf-8")
ck("activation record status","Status: **EXECUTED**" in record)
ck("activation record network","axven-devnet-2 CANONICAL" in record)
ck("activation record decision","CD-003" in record)
print(f"POST-ACTIVATION AUDIT: {len(c)}/{len(c)} GREEN")
