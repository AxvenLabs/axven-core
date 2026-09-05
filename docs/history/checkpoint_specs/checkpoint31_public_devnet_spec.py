#!/usr/bin/env python3
from pathlib import Path
R=Path(__file__).resolve().parent
checks=[]
def ok(n,x): assert x,n; checks.append(n)
for p in ["PUBLIC_DEVNET_ACCEPTANCE.md","SEED_OPERATIONS.md","tools/seed_health.py"]:
    ok(p,(R/p).is_file())
acc=(R/"PUBLIC_DEVNET_ACCEPTANCE.md").read_text(encoding="utf-8")
ops=(R/"SEED_OPERATIONS.md").read_text(encoding="utf-8")
health=(R/"tools/seed_health.py").read_text(encoding="utf-8")
ok("canonical chain id","axven-devnet-2" in acc)
ok("canonical seed","seed.axven.org:18444" in acc)
ok("block 1 recorded","006773650210f2c0fbe1eb97526e294bc7343a6aec1a5617889803cf489c04eb" in acc)
ok("block 2 recorded","002fdc15afd2f247ae3239b205486d0f482107c45b448528edcd52730f888edd" in acc)
ok("height 2 persistence","height `2`" in acc)
ok("chainwork 768 persistence","`768`" in acc)
ok("rpc remains loopback","127.0.0.1:18443" in ops)
ok("explorer remains loopback","127.0.0.1:18445" in ops)
ok("health expected fingerprint","EXPECTED_FINGERPRINT" in health)
ok("health min height","--min-height" in health)
print(f"Checkpoint 31 public devnet spec: {len(checks)}/{len(checks)} GREEN")
