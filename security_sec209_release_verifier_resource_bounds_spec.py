#!/usr/bin/env python3
"""SEC-209: release verification must bound manifest and payload reads."""
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


def main() -> None:
    checks = 0

    assert verify_release.MAX_RELEASE_MANIFEST_BYTES == 1024 * 1024
    assert 4096 <= verify_release.HASH_CHUNK_BYTES <= 1024 * 1024
    assert Path("release_manifest.json").stat().st_size < verify_release.MAX_RELEASE_MANIFEST_BYTES
    checks += 1
    print("[GREEN] manifest and streaming-hash memory budgets are finite with current headroom")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        manifest_path = root / "release_manifest.json"
        with manifest_path.open("wb") as handle:
            handle.seek(verify_release.MAX_RELEASE_MANIFEST_BYTES)
            handle.write(b"x")
        rc, stderr = _verify_staged(root, "0" * 64)
        assert rc == 2
        assert "release_manifest.json exceeds" in stderr
    checks += 1
    print("[GREEN] oversized manifest is rejected before trust-anchor hashing or JSON parsing")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        manifest_path = root / "release_manifest.json"
        manifest_path.write_bytes(b"{" + b" " * (verify_release.MAX_RELEASE_MANIFEST_BYTES - 1))
        anchor = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        rc, stderr = _verify_staged(root, anchor)
        assert rc == 2
        assert "invalid release manifest" in stderr
        assert "exceeds" not in stderr
    checks += 1
    print("[GREEN] exact manifest byte boundary reaches the canonical parser")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        payload = root / "payload.txt"
        payload.write_bytes(b"ok")
        manifest_path = root / "release_manifest.json"
        manifest_path.write_bytes(_manifest_bytes({
            "payload.txt": {
                "bytes": 2,
                "sha256": hashlib.sha256(b"ok").hexdigest(),
            }
        }))
        anchor = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        payload.write_bytes(b"x" * (verify_release.HASH_CHUNK_BYTES * 4))
        rc, stderr = _verify_staged(root, anchor)
        assert rc == 2
        assert "size mismatch: payload.txt" in stderr
    checks += 1
    print("[GREEN] oversized authenticated payload replacement is rejected at metadata size gate")

    with TemporaryDirectory() as tmp:
        staged = Path(tmp).resolve() / "release"
        trusted_digest = build_release_package.build(staged)
        original_read_bytes = Path.read_bytes

        def forbidden_read_bytes(self):
            raise AssertionError(f"unbounded Path.read_bytes reached by verifier: {self}")

        Path.read_bytes = forbidden_read_bytes
        try:
            rc, stderr = _verify_staged(staged, trusted_digest)
        finally:
            Path.read_bytes = original_read_bytes
        assert rc == 0, stderr
    checks += 1
    print("[GREEN] healthy release verification performs no unbounded Path.read_bytes call")

    source = Path("verify_release.py").read_text(encoding="utf-8")
    assert "MANIFEST.read_bytes()" not in source
    assert "candidate.read_bytes()" not in source
    assert "MAX_RELEASE_MANIFEST_BYTES" in source
    assert "HASH_CHUNK_BYTES" in source
    assert ".read(1)" in source
    checks += 1
    print("[GREEN] production verifier uses bounded manifest input and capped streaming payload hashing")

    manifest = json.loads(Path("release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "verify_release.py",
        "security_sec205_release_manifest_trust_anchor_spec.py",
        "security_sec207_release_unlisted_payload_containment_spec.py",
        "security_sec209_release_verifier_resource_bounds_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] release manifest covers verifier and SEC-205/207/209 contracts")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-209 leaves canonical chain identity unchanged")

    assert checks == 8, checks
    print("SEC-209 release verifier resource bounds: 8/8 GREEN")


if __name__ == "__main__":
    main()
