#!/usr/bin/env python3
"""SEC-107 immutable GitHub Actions dependency pins contract."""

import re
from pathlib import Path


WORKFLOW = Path(".github/workflows/validation.yml")
EXPECTED = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
}


def main():
    text = WORKFLOW.read_text(encoding="utf-8")
    uses = re.findall(r"^\s*-\s+uses:\s+([^\s#]+)", text, re.MULTILINE)
    assert uses, "validation workflow has no action dependencies"
    print("[GREEN] validation workflow action dependencies discovered")

    parsed = {}
    for item in uses:
        assert "@" in item, f"action dependency lacks ref: {item}"
        name, ref = item.rsplit("@", 1)
        assert re.fullmatch(r"[0-9a-f]{40}", ref), (
            f"action dependency is not immutable SHA-pinned: {item}"
        )
        parsed[name] = ref
    print("[GREEN] every validation action uses an immutable 40-hex commit SHA")

    assert parsed == EXPECTED, (
        f"unexpected validation action set or pin: {parsed!r}"
    )
    print("[GREEN] approved checkout/setup-python action commits pinned exactly")

    forbidden = ("@main", "@master", "@v1", "@v2", "@v3", "@v4", "@v5", "@v6", "@v7", "@latest")
    assert not any(token in text for token in forbidden), (
        "moving GitHub Actions ref reintroduced"
    )
    print("[GREEN] moving GitHub Actions tags and branches absent")

    print("SEC-107 immutable GitHub Actions pins: 4/4 GREEN")


if __name__ == "__main__":
    main()
