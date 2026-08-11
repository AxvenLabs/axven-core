#!/usr/bin/env python3
from pathlib import Path
import json, axven

ROOT=Path(__file__).resolve().parent
c=[]
def ok(n,x): assert x,n; c.append(n)

ok("chain id",axven.CHAIN_ID=="axven-devnet-2")
ok("fingerprint",axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae")
ok("genesis",axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3")

for name in ["README.md","LICENSE","SECURITY.md","CONTRIBUTING.md","CHANGELOG.md","RELEASE_CHECKLIST.md",".gitignore"]:
    ok("release file "+name,(ROOT/name).is_file())

readme=(ROOT/"README.md").read_text(encoding="utf-8")
ok("readme devnet warning","not a production mainnet" in readme.lower())
sec=(ROOT/"SECURITY.md").read_text(encoding="utf-8")
ok("security no audit claim","independent security review" in sec.lower())
checklist=(ROOT/"RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
ok("whitepaper remains pending","[ ] final whitepaper" in checklist.lower())

m=json.loads((ROOT/"release_manifest.json").read_text(encoding="utf-8"))
ok("activation executed",m.get("activation")=="EXECUTED")
ok("canonical true",m.get("canonical") is True)

print(f"Public release spec: {len(c)}/{len(c)} GREEN")
