#!/usr/bin/env python3
"""SEC-207: authenticated releases must reject every appended payload file."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import axven
import build_release_package
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
    return _verify_staged(root, anchor)


def _verify_staged(root: Path, anchor: str) -> int:
    original_root = verify_release.ROOT
    original_manifest = verify_release.MANIFEST
    verify_release.ROOT = root.resolve()
    verify_release.MANIFEST = (root / "release_manifest.json").resolve()
    try:
        return verify_release.main([anchor])
    finally:
        verify_release.ROOT = original_root
        verify_release.MANIFEST = original_manifest


def main():
    checks = 0

    manifest_path = Path("release_manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    with TemporaryDirectory() as tmp:
        staged = Path(tmp).resolve() / "release"
        trusted_digest = build_release_package.build(staged)
        assert _verify_staged(staged, trusted_digest) == 0
    checks += 1
    print("[GREEN] manifest-defined builder produces an exact verifiable release inventory")

    with TemporaryDirectory() as tmp:
        staged = Path(tmp).resolve() / "release"
        trusted_digest = build_release_package.build(staged)
        (staged / "NOTES.md").write_text("appended after release build\n", encoding="utf-8")
        assert _verify_staged(staged, trusted_digest) == 2
    checks += 1
    print("[GREEN] even inert-looking appended files are rejected from the verified release asset")

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

    with TemporaryDirectory() as tmp:
        output = Path(tmp).resolve() / "already-exists"
        output.mkdir()
        try:
            build_release_package.build(output)
        except RuntimeError as exc:
            assert "must not already exist" in str(exc)
        else:
            raise AssertionError("release builder accepted a pre-existing output directory")
    checks += 1
    print("[GREEN] release builder refuses stale/pre-populated output directories")

    notes = Path("GITHUB_RELEASE.md").read_text(encoding="utf-8")
    checklist = Path("RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
    assert "Release payload inventory" in notes
    assert "build_release_package.py" in notes
    assert "before setup" in notes
    assert "single extra file" in " ".join(notes.split())
    assert "build_release_package.py" in checklist
    checks += 1
    print("[GREEN] release guidance requires clean manifest-defined staging before publication")

    for name in (
        "verify_release.py",
        "build_release_package.py",
        "GITHUB_RELEASE.md",
        "RELEASE_CHECKLIST.md",
        "security_sec205_release_manifest_trust_anchor_spec.py",
        "security_sec207_release_unlisted_payload_containment_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] authenticated manifest covers the builder, verifier, guidance, and regressions")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] canonical chain identity unchanged")

    assert checks == 10, checks
    print("SEC-207 exact release payload containment: 10/10 GREEN")


if __name__ == "__main__":
    main()
