#!/usr/bin/env python3
"""SEC-107 immutable GitHub Actions dependency pins contract."""

import re
from pathlib import Path


WORKFLOW = Path(".github/workflows/validation.yml")
EXPECTED = {
    "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
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

    forbidden = ("@main", "@master", "@v1", "@v2", "@v3", "@v4", "@v5", "@latest")
    assert not any(token in text for token in forbidden), (
        "moving GitHub Actions ref reintroduced"
    )
    print("[GREEN] moving GitHub Actions tags and branches absent")

    print("SEC-107 immutable GitHub Actions pins: 4/4 GREEN")


if __name__ == "__main__":
    main()
