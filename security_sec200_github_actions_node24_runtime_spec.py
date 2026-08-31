#!/usr/bin/env python3
"""SEC-200: validation actions must use reviewed native Node 24 releases."""

import re
from pathlib import Path

WORKFLOW = Path(".github/workflows/validation.yml")
CHECKOUT_PIN = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_PIN = "5fda3b95a4ea91299a34e894583c3862153e4b97"
OLD_NODE20_PINS = {
    "11d5960a326750d5838078e36cf38b85af677262",
    "a26af69be951a213d495a4c3e4e4022e16d87065",
}

def main():
    checks = []
    def green(name, condition=True):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    text = WORKFLOW.read_text(encoding="utf-8")
    uses = re.findall(r"^\s*-\s+uses:\s+([^\s#]+)", text, re.MULTILINE)
    parsed = dict(item.rsplit("@", 1) for item in uses)
    green(
        "validation pins reviewed checkout/setup-python Node 24 releases",
        parsed == {
            "actions/checkout": CHECKOUT_PIN,
            "actions/setup-python": SETUP_PYTHON_PIN,
        },
    )
    green(
        "retired Node 20-era action commits are absent",
        all(pin not in text for pin in OLD_NODE20_PINS),
    )
    green(
        "reviewed upstream release provenance is documented in workflow",
        f"actions/checkout@{CHECKOUT_PIN} # v7.0.1" in text
        and f"actions/setup-python@{SETUP_PYTHON_PIN} # v7.0.0" in text,
    )

    permission_block = re.search(
        r"(?ms)^permissions:\s*\n((?:^[ \t]+[^\n]+\n?)*)", text
    )
    entries = {}
    if permission_block:
        for line in permission_block.group(1).splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            key, value = stripped.split(":", 1)
            entries[key.strip()] = value.strip()
    green(
        "Node 24 migration preserves read-only checkout boundary",
        entries == {"contents": "read"}
        and "persist-credentials: false" in text
        and "pull_request_target" not in text
        and "workflow_run" not in text,
    )
    green(
        "runtime and hash-locked dependency policy remain pinned",
        'python-version: "3.13.15"' in text
        and text.count("--require-hashes") >= 2
        and text.count("--only-binary=:all:") >= 2
        and '--no-build-isolation --no-deps -e ".[legacy-mldsa-recovery]"' in text,
    )
    assert len(checks) == 5
    print("SEC-200 GitHub Actions Node 24 runtime: 5/5 GREEN")

if __name__ == "__main__":
    main()
