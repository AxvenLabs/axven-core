#!/usr/bin/env python3
"""SEC-207: authenticated releases must reject appended active payloads."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import axven
import verify_release


def _manifest_bytes(files):
    return (json.dumps({"files": files}, indent=2) + "\n").encode("utf-8")


def _entry(path: Path):
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _verify_temp(root: Path, files) -> int:
    manifest = root / "release_manifest.json"
    manifest.write_bytes(_manifest_bytes(files))
    anchor = hashlib.sha256(manifest.read_bytes()).hexdigest()
    original_root = verify_release.ROOT
    original_manifest = verify_release.MANIFEST
    verify_release.ROOT = root.resolve()
    verify_release.MANIFEST = manifest.resolve()
    try:
        return verify_release.main([anchor])
    finally:
        verify_release.ROOT = original_root
        verify_release.MANIFEST = original_manifest


def main():
    checks = 0

    manifest_path = Path("release_manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    trusted_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert verify_release.main([trusted_digest]) == 0
    checks += 1
    print("[GREEN] canonical release tree has no unmanifested active payload")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        payload = root / "payload.txt"
        payload.write_text("trusted payload\n", encoding="utf-8")
        files = {"payload.txt": _entry(payload)}

        # Inert docs and repository-host metadata are intentionally outside the
        # active payload allow-list so source checkouts remain verifiable.
        (root / "NOTES.md").write_text("notes\n", encoding="utf-8")
        (root / ".github").mkdir()
        (root / ".github" / "metadata.yml").write_text("name: metadata\n", encoding="utf-8")
        assert _verify_temp(root, files) == 0
    checks += 1
    print("[GREEN] inert documentation and GitHub metadata do not create a false positive")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        payload = root / "payload.txt"
        payload.write_text("trusted payload\n", encoding="utf-8")
        files = {"payload.txt": _entry(payload)}
        (root / "sitecustomize.py").write_text("raise SystemExit('injected')\n", encoding="utf-8")
        assert _verify_temp(root, files) == 2
    checks += 1
    print("[GREEN] appended Python auto-import payload is rejected")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        payload = root / "payload.txt"
        payload.write_text("trusted payload\n", encoding="utf-8")
        files = {"payload.txt": _entry(payload)}
        data_dir = root / "axven-data"
        data_dir.mkdir()
        (data_dir / "peers.json").write_text("[]\n", encoding="utf-8")
        assert _verify_temp(root, files) == 2
    checks += 1
    print("[GREEN] appended runtime configuration/data payload is rejected")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        payload = root / "payload.txt"
        payload.write_text("trusted payload\n", encoding="utf-8")
        files = {"payload.txt": _entry(payload)}
        scripts = root / ".venv" / "Scripts"
        scripts.mkdir(parents=True)
        (scripts / "python.exe").write_bytes(b"not-a-real-executable")
        assert _verify_temp(root, files) == 2
    checks += 1
    print("[GREEN] appended virtual-environment executable payload is rejected")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        payload = root / "payload.txt"
        payload.write_text("trusted payload\n", encoding="utf-8")
        noncanonical = {
            "nested/../payload.txt": _entry(payload),
        }
        assert _verify_temp(root, noncanonical) == 2
    checks += 1
    print("[GREEN] authenticated manifest paths must use one canonical relative spelling")

    notes = Path("GITHUB_RELEASE.md").read_text(encoding="utf-8")
    assert "Release payload inventory" in notes
    assert "before setup" in notes
    assert "sitecustomize.py" in notes
    assert "unmanifested" in notes
    checks += 1
    print("[GREEN] release guidance requires inventory verification before setup or launch")

    for name in (
        "verify_release.py",
        "GITHUB_RELEASE.md",
        "security_sec207_release_unlisted_payload_containment_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] authenticated manifest covers SEC-207 verifier, guidance, and regression")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] canonical chain identity unchanged")

    assert checks == 9, checks
    print("SEC-207 unmanifested release payload containment: 9/9 GREEN")


if __name__ == "__main__":
    main()
