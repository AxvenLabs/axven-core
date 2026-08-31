#!/usr/bin/env python3
"""SEC-205: release verification must start from an external trust anchor."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import axven
import verify_release


def _manifest_bytes(files):
    return (json.dumps({"files": files}, indent=2) + "\n").encode("utf-8")


def main():
    checks = 0

    assert verify_release.main([]) == 2
    assert verify_release.main(["not-a-sha256"]) == 2
    checks += 1
    print("[GREEN] release verification fails closed without a canonical 64-hex trust anchor")

    assert verify_release.main(["0" * 64]) == 2
    checks += 1
    print("[GREEN] release verification rejects a mismatched external manifest digest")

    manifest_path = Path("release_manifest.json")
    trusted_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert verify_release.main([trusted_digest]) == 0
    checks += 1
    print("[GREEN] exact external manifest digest unlocks normal release integrity verification")

    original_root = verify_release.ROOT
    original_manifest = verify_release.MANIFEST
    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        payload = root / "payload.txt"
        payload.write_bytes(b"trusted payload\n")
        entry = {
            "payload.txt": {
                "bytes": payload.stat().st_size,
                "sha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
            }
        }
        package_manifest = root / "release_manifest.json"
        package_manifest.write_bytes(_manifest_bytes(entry))
        anchor = hashlib.sha256(package_manifest.read_bytes()).hexdigest()

        verify_release.ROOT = root
        verify_release.MANIFEST = package_manifest
        try:
            assert verify_release.main([anchor]) == 0
            package_manifest.write_bytes(_manifest_bytes({
                "payload.txt": {
                    "bytes": payload.stat().st_size,
                    "sha256": "f" * 64,
                }
            }))
            assert verify_release.main([anchor]) == 2
        finally:
            verify_release.ROOT = original_root
            verify_release.MANIFEST = original_manifest
    checks += 1
    print("[GREEN] changing the bundled manifest cannot preserve an already trusted external digest")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        outside = root.parent / "sec205-outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        escape_manifest = root / "release_manifest.json"
        escape_entry = {
            "../sec205-outside.txt": {
                "bytes": outside.stat().st_size,
                "sha256": hashlib.sha256(outside.read_bytes()).hexdigest(),
            }
        }
        escape_manifest.write_bytes(_manifest_bytes(escape_entry))
        anchor = hashlib.sha256(escape_manifest.read_bytes()).hexdigest()
        verify_release.ROOT = root
        verify_release.MANIFEST = escape_manifest
        try:
            assert verify_release.main([anchor]) == 2
        finally:
            verify_release.ROOT = original_root
            verify_release.MANIFEST = original_manifest
            outside.unlink(missing_ok=True)
    checks += 1
    print("[GREEN] authenticated manifests still cannot escape the release root")

    release_notes = Path("GITHUB_RELEASE.md").read_text(encoding="utf-8")
    checklist = Path("RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
    assert "GitHub release body" in release_notes
    assert "MUST NOT" in release_notes and "downloaded release archive" in release_notes
    assert "verify_release.py <TRUSTED_RELEASE_MANIFEST_SHA256>" in release_notes
    assert "outside the downloadable release package/assets" in checklist
    assert "verify_release.py <TRUSTED_RELEASE_MANIFEST_SHA256>" in checklist
    checks += 1
    print("[GREEN] release process requires the trust anchor to be published outside release assets")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name in (
        "verify_release.py",
        "GITHUB_RELEASE.md",
        "RELEASE_CHECKLIST.md",
        "security_sec205_release_manifest_trust_anchor_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] authenticated manifest covers verifier, release guidance, checklist, and SEC-205 regression")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] canonical chain identity unchanged")

    assert checks == 8, checks
    print("SEC-205 release manifest trust anchor: 8/8 GREEN")


if __name__ == "__main__":
    main()
