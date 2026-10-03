#!/usr/bin/env python3
"""ARCH-001 research-only PQ/hybrid authorization timing diagnostic protocol.

Repeats the existing authorization-cost fixture in fresh interpreter processes
and records reproducibility metadata plus timing dispersion. Wall-clock values
remain diagnostic: they are deliberately NOT canonical decision evidence,
consensus parameters, architecture scores, or SLAs.
"""
from __future__ import annotations

import json
import platform
from pathlib import Path
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "arch001_auth_cost_compare.py"
RUNS = 5
SCHEMES = ("ed25519", "ml-dsa-44", "hybrid")


def run_once() -> dict[str, tuple[int, int]]:
    proc = subprocess.run(
        [sys.executable, str(FIXTURE)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr
    rows: dict[str, tuple[int, int]] = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) == 5 and parts[0] in SCHEMES:
            assert parts[1] == "canonical_witness_bytes"
            assert parts[3] == "median_verify_ns"
            rows[parts[0]] = (int(parts[2]), int(parts[4]))
    assert tuple(rows) == SCHEMES
    assert all(size > 0 and timing > 0 for size, timing in rows.values())
    return rows


def main() -> None:
    runs = [run_once() for _ in range(RUNS)]

    summary = {}
    for scheme in SCHEMES:
        sizes = [row[scheme][0] for row in runs]
        timings = [row[scheme][1] for row in runs]
        assert len(set(sizes)) == 1
        median = int(statistics.median(timings))
        minimum = min(timings)
        maximum = max(timings)
        assert minimum > 0
        summary[scheme] = {
            "canonical_witness_bytes": sizes[0],
            "process_runs": RUNS,
            "median_of_process_medians_ns": median,
            "min_process_median_ns": minimum,
            "max_process_median_ns": maximum,
            "max_over_min_ratio": round(maximum / minimum, 6),
        }

    assert summary["ed25519"]["canonical_witness_bytes"] < summary["ml-dsa-44"]["canonical_witness_bytes"]
    assert summary["ed25519"]["canonical_witness_bytes"] < summary["hybrid"]["canonical_witness_bytes"]

    evidence = {
        "schema": "axven-arch001-auth-timing-diagnostic-v1",
        "scope": "research-only; outside production consensus routing",
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "runs_are_fresh_processes": True,
        "timings_are_diagnostic_only": True,
        "timings_are_not_canonical": True,
        "architecture_selected": False,
        "schemes": summary,
    }
    print(f"ARCH-001 auth timing diagnostic protocol: {RUNS}/{RUNS} process runs GREEN")
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    print("NOTE wall-clock timing is environment-sensitive and excluded from canonical decision evidence; no architecture selected")


if __name__ == "__main__":
    main()
