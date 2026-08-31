#!/usr/bin/env python3
"""SEC-108 least-privilege GitHub Actions token/checkout contract."""

import re
from pathlib import Path


WORKFLOW = Path(".github/workflows/validation.yml")
CHECKOUT_PIN = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_PIN = "5fda3b95a4ea91299a34e894583c3862153e4b97"


def main():
    text = WORKFLOW.read_text(encoding="utf-8")

    permission_block = re.search(
        r"(?ms)^permissions:\s*\n((?:^[ \t]+[^\n]+\n?)*)",
        text,
    )
    assert permission_block, "workflow permissions must be explicit"
    entries = {}
    for line in permission_block.group(1).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, value = stripped.split(":", 1)
        entries[key.strip()] = value.strip()
    assert entries == {"contents": "read"}, (
        f"workflow token permissions exceed approved read-only scope: {entries!r}"
    )
    print("[GREEN] workflow token scope explicitly pinned to contents: read")

    checkout = re.search(
        rf"(?ms)^\s*-\s+uses:\s+actions/checkout@{CHECKOUT_PIN}[^\n]*\n"
        r"(?P<body>(?:^\s{8,}[^\n]*\n?)*)",
        text,
    )
    assert checkout, "immutable checkout action pin missing"
    assert re.search(
        r"(?m)^\s+persist-credentials:\s*false\s*$",
        checkout.group("body"),
    ), "checkout credentials must not persist in git config"
    print("[GREEN] checkout persistence explicitly disabled")

    assert f"actions/setup-python@{SETUP_PYTHON_PIN}" in text
    assert "contents: write" not in text
    assert "write-all" not in text
    assert re.search(r"(?m)^permissions:\s*$", text)
    print("[GREEN] immutable action pins remain intact without write grants")

    forbidden = (
        "pull-requests: write",
        "issues: write",
        "actions: write",
        "packages: write",
        "security-events: write",
        "id-token: write",
    )
    assert not any(token in text for token in forbidden)
    print("[GREEN] privileged GitHub token capabilities remain absent")

    print("SEC-108 GitHub Actions least privilege: 4/4 GREEN")


if __name__ == "__main__":
    main()
