#!/usr/bin/env python3
"""SEC-210: final release inventory must reject post-hash path-state drift."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import axven
import build_release_package
import verify_release


def _manifest_bytes(files) -> bytes:
    return (json.dumps({"files": files}, indent=2) + "\n").encode("utf-8")


def _verify_staged(root: Path, anchor: str) -> tuple[int, str]:
    original_root = verify_release.ROOT
    original_manifest = verify_release.MANIFEST
    verify_release.ROOT = root.resolve()
    verify_release.MANIFEST = (root / "release_manifest.json").resolve()
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stderr(stderr):
            rc = verify_release.main([anchor])
        return rc, stderr.getvalue()
    finally:
        verify_release.ROOT = original_root
        verify_release.MANIFEST = original_manifest


def _verify_after_payload_hash_mutation(mutation) -> tuple[int, str]:
    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        payload = root / "payload.txt"
        payload_bytes = b"trusted payload\n"
        payload.write_bytes(payload_bytes)
        manifest = root / "release_manifest.json"
        manifest.write_bytes(_manifest_bytes({
            "payload.txt": {
                "bytes": len(payload_bytes),
                "sha256": hashlib.sha256(payload_bytes).hexdigest(),
            }
        }))
        anchor = hashlib.sha256(manifest.read_bytes()).hexdigest()

        original_hash = verify_release._hash_payload_exact_bounded
        mutated = False

        def hash_then_mutate(path: Path, expected_bytes: int):
            nonlocal mutated
            digest = original_hash(path, expected_bytes)
            if not mutated and path.name == "payload.txt" and digest is not None:
                mutation(path)
                mutated = True
            return digest

        verify_release._hash_payload_exact_bounded = hash_then_mutate
        try:
            rc, stderr = _verify_staged(root, anchor)
        finally:
            verify_release._hash_payload_exact_bounded = original_hash
        assert mutated
        return rc, stderr


def main() -> None:
    checks = 0

    with TemporaryDirectory() as tmp:
        staged = Path(tmp).resolve() / "release"
        trusted_digest = build_release_package.build(staged)
        rc, stderr = _verify_staged(staged, trusted_digest)
        assert rc == 0, stderr
    checks += 1
    print("[GREEN] stable manifest-defined release inventory still verifies")

    rc, stderr = _verify_after_payload_hash_mutation(lambda path: path.unlink())
    assert rc == 2
    assert "missing verified release file after hashing: payload.txt" in stderr
    checks += 1
    print("[GREEN] payload deletion after authenticated hashing is rejected by final inventory")

    def replace_with_directory(path: Path) -> None:
        path.unlink()
        path.mkdir()

    rc, stderr = _verify_after_payload_hash_mutation(replace_with_directory)
    assert rc == 2
    assert "expected release file became directory: payload.txt" in stderr
    checks += 1
    print("[GREEN] payload file-to-directory drift after hashing is rejected")

    source = Path("verify_release.py").read_text(encoding="utf-8")
    assert "seen_expected" in source
    assert "expected - seen_expected" in source
    assert "expected release file became directory" in source
    assert "missing verified release file after hashing" in source
    checks += 1
    print("[GREEN] production final sweep accounts for every authenticated expected path")

    manifest = json.loads(Path("release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "verify_release.py",
        "security_sec207_release_unlisted_payload_containment_spec.py",
        "security_sec209_release_verifier_resource_bounds_spec.py",
        "security_sec210_release_final_state_stability_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] release manifest covers exact-inventory, resource-bound, and final-state contracts")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-210 leaves canonical chain identity unchanged")

    assert checks == 6, checks
    print("SEC-210 release final-state stability: 6/6 GREEN")


if __name__ == "__main__":
    main()
