#!/usr/bin/env python3
"""SEC-208: legacy release/tag provenance must remain quarantined."""
from __future__ import annotations

import json
import re
from pathlib import Path

import axven

LEGACY_TAG = "v0.9.0-devnet"
LEGACY_COMMIT = "2c144be2a1139cc3253ef98bac05d7acef2485b6"
NEXT_TAG = "v0.9.0-devnet.1"


def main() -> None:
    checks = 0
    notes = Path("GITHUB_RELEASE.md").read_text(encoding="utf-8")
    checklist = Path("RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
    version = Path("VERSION").read_text(encoding="utf-8").strip()
    metadata = json.loads(Path("RELEASE_METADATA.json").read_text(encoding="utf-8"))
    notes_flat = " ".join(notes.split())
    checklist_flat = " ".join(checklist.split())
    manifest = json.loads(Path("release_manifest.json").read_text(encoding="utf-8"))

    assert f"Planned tag: `{NEXT_TAG}`" in notes
    assert f"Tag: `{LEGACY_TAG}`" not in notes
    assert NEXT_TAG != LEGACY_TAG
    checks += 1
    print("[GREEN] release plan uses a fresh tag instead of reusing the historical prerelease tag")

    assert LEGACY_TAG in notes and LEGACY_COMMIT in notes
    assert "legacy/superseded" in notes.lower()
    assert "never retarget, delete, or reuse it" in notes_flat.lower()
    checks += 1
    print("[GREEN] historical release identity is explicitly quarantined and commit-pinned")

    assert "SEC-205" in notes and "SEC-207" in notes
    assert "MUST NOT be treated as the current hardened" in notes
    checks += 1
    print("[GREEN] legacy prerelease cannot be represented as the hardened SEC-205/207 package")

    assert "fresh previously-unused tag" in notes
    assert "If the tag already exists, stop" in notes
    assert "rather than moving it" in notes
    checks += 1
    print("[GREEN] release guidance fails closed on an already-existing tag")

    assert "git show-ref --verify --quiet refs/tags/v0.9.0-devnet.1" in checklist
    assert "stop if that command succeeds" in checklist
    assert "git rev-parse HEAD" in checklist
    assert "git rev-parse 'v0.9.0-devnet.1^{commit}'" in checklist
    assert "equals the recorded validated commit" in checklist
    checks += 1
    print("[GREEN] checklist binds tag creation to an exact fully validated commit")

    assert "never move an existing release tag" in checklist
    assert "exact immutable tag/commit" in checklist
    assert LEGACY_TAG in checklist and LEGACY_COMMIT in checklist
    checks += 1
    print("[GREEN] checklist forbids release-tag retargeting and preserves legacy provenance")

    planned = re.findall(r"Planned tag: `([^`]+)`", notes)
    assert planned == [NEXT_TAG]
    assert re.fullmatch(r"v0\.9\.0-devnet\.1", planned[0])
    checks += 1
    print("[GREEN] planned release tag has one canonical spelling")

    assert version == NEXT_TAG
    assert metadata["tag"] == NEXT_TAG
    assert metadata["version"] == NEXT_TAG
    assert NEXT_TAG in metadata["release_name"]
    assert manifest["tag"] == NEXT_TAG
    assert manifest["version"] == NEXT_TAG
    assert NEXT_TAG in manifest["release"]
    checks += 1
    print("[GREEN] VERSION, release metadata, and release manifest share the fresh tag identity")

    for name in (
        "GITHUB_RELEASE.md",
        "RELEASE_CHECKLIST.md",
        "RELEASE_METADATA.json",
        "VERSION",
        "security_sec208_legacy_release_provenance_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] release manifest covers SEC-208 guidance, metadata, and regression")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-208 leaves canonical chain identity unchanged")

    print(f"SEC-208 legacy release provenance: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
