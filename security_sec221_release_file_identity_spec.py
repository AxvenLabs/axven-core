#!/usr/bin/env python3
"""SEC-221: release verification must bind hashes to stable final files."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

import axven
import build_release_package
import verify_release


ROOT = Path(__file__).resolve().parent


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


def _write_release(root: Path, payload: bytes) -> str:
    target = root / "payload.txt"
    target.write_bytes(payload)
    manifest = root / "release_manifest.json"
    manifest.write_bytes(
        _manifest_bytes(
            {
                "payload.txt": {
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            }
        )
    )
    return hashlib.sha256(manifest.read_bytes()).hexdigest()


def _verify_after_payload_hash_mutation(mutation) -> tuple[int, str]:
    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        payload_bytes = b"authenticated release payload\n"
        anchor = _write_release(root, payload_bytes)

        original_hash = verify_release._hash_payload_exact_bounded
        mutated = False

        def hash_then_mutate(path: Path, expected_bytes: int):
            nonlocal mutated
            digest = original_hash(path, expected_bytes)
            if not mutated and path.name == "payload.txt" and digest is not None:
                mutation(path, expected_bytes)
                mutated = True
            return digest

        verify_release._hash_payload_exact_bounded = hash_then_mutate
        try:
            rc, stderr = _verify_staged(root, anchor)
        finally:
            verify_release._hash_payload_exact_bounded = original_hash
        assert mutated
        return rc, stderr


def _file_record(path: Path) -> dict:
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def main() -> None:
    checks = 0

    with TemporaryDirectory() as tmp:
        staged = Path(tmp).resolve() / "release"
        trusted_digest = build_release_package.build(staged)
        rc, stderr = _verify_staged(staged, trusted_digest)
        assert rc == 0, stderr
    checks += 1
    print("[GREEN] stable manifest-defined release still verifies")

    def replace_same_size(path: Path, expected_bytes: int) -> None:
        replacement = path.with_name("replacement.tmp")
        replacement.write_bytes(b"X" * expected_bytes)
        assert replacement.stat().st_size == path.stat().st_size
        os.replace(replacement, path)

    rc, stderr = _verify_after_payload_hash_mutation(replace_same_size)
    assert rc == 2
    assert "verified release file content changed after hashing: payload.txt" in stderr
    checks += 1
    print("[GREEN] same-size regular-file replacement after authenticated hashing is rejected")

    def rewrite_same_inode(path: Path, expected_bytes: int) -> None:
        before = path.stat()
        path.write_bytes(b"Y" * expected_bytes)
        after = path.stat()
        assert after.st_size == before.st_size

    rc, stderr = _verify_after_payload_hash_mutation(rewrite_same_inode)
    assert rc == 2
    assert "verified release file content changed after hashing: payload.txt" in stderr
    checks += 1
    print("[GREEN] same-size in-place payload mutation after authenticated hashing is rejected")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        anchor = _write_release(root, b"manifest identity payload\n")
        original_read = verify_release._read_manifest_bounded
        swapped = False

        def read_then_replace(path: Path, metadata):
            nonlocal swapped
            data = original_read(path, metadata)
            if not swapped:
                replacement = path.with_name("manifest-replacement.tmp")
                replacement.write_bytes(b"Z" * len(data))
                assert replacement.stat().st_size == metadata.st_size
                os.replace(replacement, path)
                swapped = True
            return data

        verify_release._read_manifest_bounded = read_then_replace
        try:
            rc, stderr = _verify_staged(root, anchor)
        finally:
            verify_release._read_manifest_bounded = original_read
        assert swapped
        assert rc == 2
        assert "verified release file content changed after hashing: release_manifest.json" in stderr
    checks += 1
    print("[GREEN] trusted manifest replacement after anchor read is rejected by final authentication")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        payload = root / "payload.txt"
        payload.write_bytes(b"descriptor-bound payload\n")
        original_same_file = verify_release._same_file
        forced_mismatch = False

        def mismatch_once(before, opened):
            nonlocal forced_mismatch
            if not forced_mismatch:
                forced_mismatch = True
                return False
            return original_same_file(before, opened)

        verify_release._same_file = mismatch_once
        try:
            try:
                verify_release._hash_payload_exact_bounded(payload, payload.stat().st_size)
            except ValueError as exc:
                assert "changed before hashing" in str(exc)
            else:
                raise AssertionError("payload descriptor identity mismatch was accepted")
        finally:
            verify_release._same_file = original_same_file
        assert forced_mismatch
    checks += 1
    print("[GREEN] payload hashing is bound to the lstat-checked opened file descriptor")

    source = (ROOT / "verify_release.py").read_text(encoding="utf-8")
    assert "os.path.samestat" in source
    assert "_verified_metadata" in source
    assert "verified release file content changed after hashing" in source
    assert "_hash_payload_exact_bounded(path, expected_bytes)" in source
    checks += 1
    print("[GREEN] production verifier carries descriptor identity into final content authentication")

    manifest = json.loads((ROOT / "release_manifest.json").read_text(encoding="utf-8"))
    expected_files = manifest["files"]
    assert expected_files.get("verify_release.py") == _file_record(ROOT / "verify_release.py")
    assert expected_files.get(Path(__file__).name) == _file_record(Path(__file__))
    checks += 1
    print("[GREEN] release manifest authenticates SEC-221 production and regression bytes")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-221 leaves canonical chain identity unchanged")

    assert checks == 8, checks
    print("SEC-221 release file identity: 8/8 GREEN")


if __name__ == "__main__":
    main()
