#!/usr/bin/env python3
from pathlib import Path

R=Path(__file__).resolve().parent
doc=(R/"CHECKPOINT_32_WALLET_TRANSFER_ACCEPTANCE.md").read_text(encoding="utf-8")
checks=[]

def ok(name, cond):
    assert cond, name
    checks.append(name)

ok("record exists", bool(doc))
ok("network id", "axven-devnet-2" in doc)
ok("seed endpoint", "seed.axven.org:18444" in doc)
ok("8 decimals", "Decimals: `8`" in doc)
ok("1 AXV base unit mapping", "100,000,000" in doc)
ok("sender address", "Nc644a8c302edef72e399e40ed63cdac78d3e77f6" in doc)
ok("recipient address", "Na4aa188e4cfbb4f0aca1e4ed74aa120f0d8f9295" in doc)
ok("txid", "f8d0359a79ced620af2e40b84e98453edfc791269cf710c1933c16bf39daf306" in doc)
ok("amount", "Amount: `1 AXV`" in doc)
ok("fee", "0.00001 AXV" in doc)
ok("confirmation height", "Height: `102`" in doc)
ok("confirmation block", "009104e354321db315c324eac7b8f0892b1d1aa13b5d7171dd5d9ab2782dcff0" in doc)
ok("chainwork", "`26368`" in doc)
ok("recipient balance", "101.00001 AXV" in doc)
ok("consensus unchanged", "does not" in doc.lower() and "change transaction validity" in doc)

print(f"Checkpoint 32 wallet transfer spec: {len(checks)}/{len(checks)} GREEN")
