#!/usr/bin/env python3
from pathlib import Path
import json, axven
ROOT=Path(__file__).resolve().parent
checks=[]
def ck(n,x):
    assert x,n; checks.append(n); print("[GREEN]",n)
ck("canonical chain",axven.CHAIN_ID=="axven-devnet-2")
ck("canonical fingerprint",axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
ck("canonical genesis",axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3")
m=json.loads((ROOT/"release_manifest.json").read_text(encoding="utf-8"))
ck("activation executed",m.get("activation")=="EXECUTED")
for name in [
 "canonical_ops.py","canonical_node1_start.ps1","canonical_node2_start.ps1",
 "canonical_node1_status.ps1","canonical_node1_mine1.ps1",
 "canonical_node2_sync_node1.ps1","canonical_stop_all.ps1",
 "CANONICAL_OPERATIONS.md"
]:
    ck("operator file "+name,(ROOT/name).is_file())
print(f"Canonical ops audit: {len(checks)}/{len(checks)} GREEN")
