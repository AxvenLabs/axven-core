#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parent
raw=(ROOT/"CD-003_ACTIVATION.md").read_bytes()
text=raw.decode("utf-8")
assert "Status: **EXECUTED**" in text
assert "axven-devnet-2 CANONICAL" in text
assert "CD-003" in text
print("Activation record UTF-8: 3/3 GREEN")
