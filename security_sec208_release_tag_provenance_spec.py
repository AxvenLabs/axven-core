#!/usr/bin/env python3
"""SEC-208: public releases must bind a fresh immutable tag to exact code and manifest."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

import axven
import release_provenance


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"git fixture command failed: {' '.join(args)}")
    return result.stdout.strip()


def _expect_runtime_error(fn, text: str) -> None:
    try:
        fn()
    except RuntimeError as exc:
        assert text in str(exc), str(exc)
    else:
        raise AssertionError(f"expected RuntimeError containing {text!r}")


def _fixture():
    temp = TemporaryDirectory()
    base = Path(temp.name).resolve()
    remote = base / "origin.git"
    work = base / "work"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "init", "-b", "main", str(work)], check=True, stdout=subprocess.DEVNULL)
    _git(work, "config", "user.name", "SEC-208")
    _git(work, "config", "user.email", "sec208@example.invalid")
    (work / "release_manifest.json").write_bytes(b'{"files": {}}\n')
    _git(work, "add", "release_manifest.json")
    _git(work, "commit", "-m", "fixture")
    _git(work, "remote", "add", "origin", str(remote))
    _git(work, "push", "-u", "origin", "main")
    return temp, work


def main():
    checks = 0

    assert release_provenance.LEGACY_RELEASE_TAGS == frozenset({"v0.9.0-devnet"})
    assert "https://github.com/AxvenLabs/axven-core" in release_provenance.CANONICAL_ORIGIN_URLS
    checks += 1
    print("[GREEN] historical public tag is permanently classified as non-reusable")

    temp, work = _fixture()
    try:
        prepared = release_provenance.prepare(
            work,
            "v0.9.0-devnet.1",
            require_canonical_origin=False,
        )
        expected_head = _git(work, "rev-parse", "HEAD")
        expected_manifest = hashlib.sha256((work / "release_manifest.json").read_bytes()).hexdigest()
        assert prepared == {
            "tag": "v0.9.0-devnet.1",
            "release_commit_sha": expected_head,
            "release_manifest_sha256": expected_manifest,
        }
        checks += 1
        print("[GREEN] clean new release tag preparation binds exact HEAD and manifest digest")

        _expect_runtime_error(
            lambda: release_provenance.prepare(
                work,
                "v0.9.0-devnet",
                require_canonical_origin=False,
            ),
            "legacy release tag",
        )
        checks += 1
        print("[GREEN] legacy v0.9.0-devnet cannot be reused even if local tag refs are absent")

        (work / "release_manifest.json").write_bytes(b'{"files": {"dirty": {}}}\n')
        _expect_runtime_error(
            lambda: release_provenance.prepare(
                work,
                "v0.9.0-devnet.2",
                require_canonical_origin=False,
            ),
            "tracked modifications",
        )
        _git(work, "restore", "release_manifest.json")
        checks += 1
        print("[GREEN] release preparation rejects a dirty tracked checkout")

        _git(work, "tag", "-a", "v0.9.0-devnet.2", "-m", "remote-existing")
        _git(work, "push", "origin", "refs/tags/v0.9.0-devnet.2")
        _git(work, "tag", "-d", "v0.9.0-devnet.2")
        _expect_runtime_error(
            lambda: release_provenance.prepare(
                work,
                "v0.9.0-devnet.2",
                require_canonical_origin=False,
            ),
            "already exists remotely",
        )
        checks += 1
        print("[GREEN] remote-only existing tag cannot be silently reused or moved")

        _git(work, "tag", "-a", "v0.9.0-devnet.3", "-m", "local-existing")
        _expect_runtime_error(
            lambda: release_provenance.prepare(
                work,
                "v0.9.0-devnet.3",
                require_canonical_origin=False,
            ),
            "already exists locally",
        )
        _git(work, "tag", "-d", "v0.9.0-devnet.3")
        checks += 1
        print("[GREEN] local existing tag cannot be silently reused or moved")

        _git(work, "tag", "-a", "v0.9.0-devnet.4", "-m", "verified")
        _git(work, "push", "origin", "refs/tags/v0.9.0-devnet.4")
        verified = release_provenance.verify(
            work,
            "v0.9.0-devnet.4",
            expected_head,
            expected_manifest,
            require_canonical_origin=False,
        )
        assert verified["release_commit_sha"] == expected_head
        assert verified["release_manifest_sha256"] == expected_manifest
        checks += 1
        print("[GREEN] published annotated tag verifies exact commit, manifest, and remote tag object")

        _expect_runtime_error(
            lambda: release_provenance.verify(
                work,
                "v0.9.0-devnet.4",
                "0" * 40,
                expected_manifest,
                require_canonical_origin=False,
            ),
            "HEAD does not match",
        )
        _expect_runtime_error(
            lambda: release_provenance.verify(
                work,
                "v0.9.0-devnet.4",
                expected_head,
                "0" * 64,
                require_canonical_origin=False,
            ),
            "manifest does not match",
        )
        checks += 1
        print("[GREEN] published commit and manifest trust-anchor mismatches fail closed")

        _git(work, "tag", "v0.9.0-devnet.5")
        _git(work, "push", "origin", "refs/tags/v0.9.0-devnet.5")
        _expect_runtime_error(
            lambda: release_provenance.verify(
                work,
                "v0.9.0-devnet.5",
                expected_head,
                expected_manifest,
                require_canonical_origin=False,
            ),
            "must be annotated",
        )
        checks += 1
        print("[GREEN] lightweight release tags are rejected in favor of annotated provenance")
    finally:
        temp.cleanup()

    notes = Path("GITHUB_RELEASE.md").read_text(encoding="utf-8")
    checklist = Path("RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
    normalized_notes = " ".join(notes.split())
    normalized_checklist = " ".join(checklist.split())
    assert "v0.9.0-devnet" in notes and "MUST NOT be reused or moved" in normalized_notes
    assert "release commit SHA: <PASTE FINAL 40-HEX COMMIT SHA HERE>" in notes
    assert "release_manifest.json SHA-256: <PASTE FINAL 64-HEX SHA-256 HERE>" in notes
    assert "release_provenance.py prepare" in notes
    assert "release_provenance.py verify" in notes
    assert "without --force" in normalized_notes
    assert "v0.9.0-devnet" in checklist and "never reuse or move" in normalized_checklist
    checks += 1
    print("[GREEN] release guidance requires fresh tag, exact commit, external manifest anchor, and no force move")

    manifest = json.loads(Path("release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "release_provenance.py",
        "GITHUB_RELEASE.md",
        "RELEASE_CHECKLIST.md",
        "security_sec208_release_tag_provenance_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] release manifest authenticates the SEC-208 provenance tool, policy, and regression")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] canonical chain identity unchanged")

    assert checks == 11, checks
    print("SEC-208 release tag provenance: 11/11 GREEN")


if __name__ == "__main__":
    main()
