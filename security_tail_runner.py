#!/usr/bin/env python3
"""Run SEC-076+ security contracts discovered from the repository."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PATTERN = re.compile(r"^security_sec(\d+)_.*_spec\.py$")
START_SEC = 76


def main():
    suites = []
    for path in ROOT.glob("security_sec*_spec.py"):
        match = PATTERN.match(path.name)
        if match and int(match.group(1)) >= START_SEC:
            suites.append((int(match.group(1)), path.name))
    suites.sort(key=lambda item: (item[0], item[1]))

    if not suites:
        raise AssertionError("no SEC-076+ security contracts discovered")

    for sec, script in suites:
        print(f"\n=== SEC-{sec:03d} tail: {script} ===", flush=True)
        result = subprocess.run([sys.executable, script], cwd=ROOT)
        if result.returncode != 0:
            raise SystemExit(result.returncode)

    print(f"SEC-076+ security tail: {len(suites)}/{len(suites)} GREEN")


if __name__ == "__main__":
    main()
