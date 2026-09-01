#!/usr/bin/env python3
"""Coverage-guided FUZZ-001 target for parser and ML-DSA wrapper surfaces."""
from __future__ import annotations

import sys
from pathlib import Path

import atheris

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

with atheris.instrument_imports(
    include=["fuzz_001_smoke", "p2p", "rpc", "wallet", "axven"]
):
    import fuzz_001_smoke


def TestOneInput(data: bytes) -> None:
    fuzz_001_smoke.exercise_one(data)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
