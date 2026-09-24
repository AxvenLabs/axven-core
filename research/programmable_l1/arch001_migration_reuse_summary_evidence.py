#!/usr/bin/env python3
"""ARCH-001 research-only canonical migration/reuse summary evidence.

Summarizes the existing qualitative compatibility matrix without assigning
architecture-selection weights. This file is not imported by production
consensus routing.
"""
from __future__ import annotations

import hashlib
import json

from arch001_migration_reuse_compare import COMPONENTS, MATRIX

CLASSES = ("preserve", "adapt", "replace", "new")


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def build_evidence() -> dict[str, object]:
    candidates = {}
    for candidate in ("utxo", "account", "object-resource"):
        row = MATRIX[candidate]
        counts = {name: sum(value == name for value in row.values()) for name in CLASSES}
        assert sum(counts.values()) == len(COMPONENTS)
        candidates[candidate] = {
            "component_count": len(COMPONENTS),
            "compatibility_class_counts": counts,
            "preserved_components": sorted(name for name, value in row.items() if value == "preserve"),
            "adapted_components": sorted(name for name, value in row.items() if value == "adapt"),
            "replaced_components": sorted(name for name, value in row.items() if value == "replace"),
            "new_components": sorted(name for name, value in row.items() if value == "new"),
        }

    # These are descriptive counts over the explicit compatibility matrix, not
    # weights or a ranking. Account and object/resource currently share the same
    # migration boundary classification; later evidence may distinguish them.
    assert candidates["utxo"]["compatibility_class_counts"] == {"preserve": 10, "adapt": 0, "replace": 0, "new": 1}
    assert candidates["account"]["compatibility_class_counts"] == {"preserve": 4, "adapt": 5, "replace": 1, "new": 1}
    assert candidates["object-resource"]["compatibility_class_counts"] == {"preserve": 4, "adapt": 5, "replace": 1, "new": 1}

    return {
        "schema": "axven-arch001-migration-reuse-summary-v1",
        "scope": "research-only; outside production consensus routing",
        "compatibility_classes": list(CLASSES),
        "candidates": candidates,
        "counts_are_unweighted": True,
        "architecture_selected": False,
    }


def main() -> None:
    first = canonical_bytes(build_evidence())
    second = canonical_bytes(build_evidence())
    assert first == second
    print("ARCH-001 migration/reuse summary evidence: 3/3 GREEN")
    print("evidence_sha256", hashlib.sha256(first).hexdigest())
    print(first.decode("ascii"))
    print("NOTE counts are descriptive compatibility evidence, not architecture scores")


if __name__ == "__main__":
    main()
