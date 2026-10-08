#!/usr/bin/env python3
"""ARCH-001 research-only PQ/hybrid authorization timing diagnostic protocol.

Repeats the existing authorization-cost fixture in fresh interpreter processes
and records reproducibility metadata plus timing dispersion. Wall-clock values
remain diagnostic: they are deliberately NOT canonical decision evidence,
consensus parameters, architecture scores, or SLAs.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
from pathlib import Path
import statistics
import subprocess
import sys

from cryptography.hazmat.backends.openssl.backend import backend

from arch001_auth_cost_compare import SAMPLES

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "arch001_auth_cost_compare.py"
RUNS = 5
SCHEMES = ("ed25519", "ml-dsa-44", "hybrid")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def parse_rows(stdout: str) -> dict[str, tuple[int, int]]:
    lines = stdout.splitlines()
    require(len(lines) == 4, "expected status plus exactly three scheme rows")
    require(lines[0] == "ARCH-001 authorization sensitivity: 5/5 GREEN", "invalid fixture status")
    rows = {}
    for expected, line in zip(SCHEMES, lines[1:]):
        parts = line.split()
        require(len(parts) == 5, "malformed scheme row")
        require(parts[0] == expected, "missing, duplicate or reordered scheme")
        require(parts[1] == "canonical_witness_bytes" and parts[3] == "median_verify_ns", "invalid measurement labels")
        size, timing = int(parts[2]), int(parts[4])
        require(size > 0 and timing > 0, "measurements must be positive")
        rows[expected] = (size, timing)
    return rows


def run_once() -> dict[str, tuple[int, int]]:
    proc = subprocess.run(
        [sys.executable, str(FIXTURE)], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=False, timeout=60,
    )
    require(proc.returncode == 0, f"fixture failed ({proc.returncode}): {proc.stderr}")
    require(not proc.stderr, f"fixture stderr: {proc.stderr}")
    return parse_rows(proc.stdout)


def source_provenance() -> dict[str, str]:
    paths = (Path(__file__), FIXTURE, ROOT.parents[1] / "axven.py")
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def main() -> None:
    provenance = source_provenance()
    runs = [run_once() for _ in range(RUNS)]
    require(source_provenance() == provenance, "source changed during diagnostic")

    summary = {}
    for scheme in SCHEMES:
        sizes = [row[scheme][0] for row in runs]
        timings = [row[scheme][1] for row in runs]
        require(len(set(sizes)) == 1, "witness sizes changed between processes")
        median = int(statistics.median(timings))
        minimum = min(timings)
        maximum = max(timings)
        require(minimum > 0, "timings must be positive")
        summary[scheme] = {
            "canonical_witness_bytes": sizes[0],
            "process_runs": RUNS,
            "median_of_process_medians_ns": median,
            "min_process_median_ns": minimum,
            "max_process_median_ns": maximum,
            "max_over_min_ratio": round(maximum / minimum, 6),
        }

    require(summary["ed25519"]["canonical_witness_bytes"] < summary["ml-dsa-44"]["canonical_witness_bytes"], "unexpected PQ size direction")
    require(summary["ed25519"]["canonical_witness_bytes"] < summary["hybrid"]["canonical_witness_bytes"], "unexpected hybrid size direction")

    evidence = {
        "schema": "axven-arch001-auth-timing-diagnostic-v2",
        "scope": "research-only; outside production consensus routing",
        "source_sha256": provenance,
        "cryptography_version": importlib.metadata.version("cryptography"),
        "openssl_version": backend.openssl_version_text(),
        "samples_per_process_median": SAMPLES,
        "raw_process_rows": runs,
        "verification_boundary": "axven.verify_input; valid single-input witnesses",
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
