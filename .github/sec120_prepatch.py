#!/usr/bin/env python3
from pathlib import Path

path = Path("axven.py")
text = path.read_text(encoding="utf-8")
old = '''            ok, reason, undo, reward, _fees = _apply_forward(
                block, self.utxo, height, self.total_issued)
'''
new = '''            ok, reason, undo, reward, _fees = _apply_forward(
                block, self.utxo, height, self.total_issued
            )
'''
if text.count(old) != 1:
    raise AssertionError(f"active-extension normalization anchor count={text.count(old)}")
path.write_bytes(text.replace(old, new, 1).replace("\r\n", "\n").encode("utf-8"))
print("SEC-120 active-extension anchor normalized")
