from pathlib import Path

DOC = Path("CHECKPOINT_36_DEVNET_TRANSACTION_REHEARSAL.md")
text = DOC.read_text(encoding="utf-8")

checks = []

def ok(name, condition):
    assert condition, name
    checks.append(name)

ok("record exists", DOC.is_file())
ok("network identity", "axven-devnet-2" in text)
ok("starting height 102", "Height: `102`" in text)
ok("starting chainwork", "26368" in text)
ok("wallet address", "Na4aa188e4cfbb4f0aca1e4ed74aa120f0d8f9295" in text)
ok("transaction id", "5f17c503e28056c7686a1dc011acfe35f557f099fc06394761b099771658dc17" in text)
ok("one AXV amount", "100000000" in text)
ok("fee recorded", "1000" in text)
ok("mempool state", "Transaction status: `mempool`" in text)
ok("reservation recorded", "Reserved: `5000000000`" in text)
ok("confirmation height", "Confirmation height: `103`" in text)
ok("confirmation block", "00aeecc39324572a93337ec68e4120093c8c17513ce58e97f29a8ab174830226" in text)
ok("confirmed state", "Transaction status: `confirmed`" in text)
ok("mempool cleared", "Mempool size after mining: `0`" in text)
ok("reservation released", "Reserved after mining: `0`" in text)
ok("change output", "4899999000" in text)
ok("final spendable", "5099999000" in text)
ok("fee accounting", "transaction fee" in text)
ok("acceptance green", "Checkpoint 36 is GREEN" in text)
ok("consensus unchanged", "changes no consensus parameters" in text)

print(f"Checkpoint 36 devnet transaction rehearsal: {len(checks)}/{len(checks)} GREEN")
