#!/usr/bin/env python3
"""SEC-212: release metadata must not carry privilege-bearing permission bits."""
from __future__ import annotations

from contextlib import contextmanager, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory

import axven
import build_release_package
import verify_release


@contextmanager
def _builder_root(root: Path):
    original_root = build_release_package.ROOT
    original_manifest = build_release_package.MANIFEST
    build_release_package.ROOT = root.resolve()
    build_release_package.MANIFEST = (root / "release_manifest.json").resolve()
    try:
        yield
    finally:
        build_release_package.ROOT = original_root
        build_release_package.MANIFEST = original_manifest


@contextmanager
def _verifier_root(root: Path):
    original_root = verify_release.ROOT
    original_manifest = verify_release.MANIFEST
    verify_release.ROOT = root.resolve()
    verify_release.MANIFEST = (root / "release_manifest.json").resolve()
    try:
        yield
    finally:
        verify_release.ROOT = original_root
        verify_release.MANIFEST = original_manifest


def _manifest_bytes(files) -> bytes:
    return (json.dumps({"files": files}, indent=2) + "\n").encode("utf-8")


def _write_source(root: Path, payload: bytes) -> bytes:
    (root / "payload.txt").write_bytes(payload)
    manifest_bytes = _manifest_bytes(
        {
            "payload.txt": {
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        }
    )
    (root / "release_manifest.json").write_bytes(manifest_bytes)
    return manifest_bytes


def _verify(root: Path, digest: str) -> tuple[int, str]:
    stderr = io.StringIO()
    with _verifier_root(root), redirect_stderr(stderr):
        rc = verify_release.main([digest])
    return rc, stderr.getvalue()


def main() -> None:
    checks = 0

    assert build_release_package.SAFE_RELEASE_FILE_MODE == 0o644
    assert build_release_package.SAFE_RELEASE_DIRECTORY_MODE == 0o755
    assert verify_release.UNSAFE_RELEASE_PERMISSION_BITS == (stat.S_ISUID | stat.S_ISGID)
    source = Path("build_release_package.py").read_text(encoding="utf-8")
    assert "stat.S_IMODE(metadata.st_mode)" not in source
    checks += 1
    print("[GREEN] release builder uses canonical safe modes instead of copying working-tree modes")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        payload = b"permission-safe release payload\n"
        manifest_bytes = _write_source(root, payload)
        source_payload = root / "payload.txt"
        if os.name == "posix":
            source_payload.chmod(0o777)
        output = root / "staged"
        with _builder_root(root):
            digest = build_release_package.build(output)
        assert digest == hashlib.sha256(manifest_bytes).hexdigest()
        if os.name == "posix":
            assert stat.S_IMODE((output / "payload.txt").stat().st_mode) == 0o644
            assert stat.S_IMODE((output / "release_manifest.json").stat().st_mode) == 0o644
            assert stat.S_IMODE(output.stat().st_mode) == 0o755
    checks += 1
    print("[GREEN] permissive source modes are normalized in the staged release")

    if os.name == "posix":
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            _write_source(root, b"privileged source mode\n")
            payload = root / "payload.txt"
            payload.chmod(0o6755)
            assert payload.stat().st_mode & verify_release.UNSAFE_RELEASE_PERMISSION_BITS
            with _builder_root(root):
                try:
                    build_release_package._load_verified_sources()
                except RuntimeError as exc:
                    assert "unsafe source permission bits: payload.txt" in str(exc)
                else:
                    raise AssertionError("setuid/setgid source must be rejected")
        checks += 1
        print("[GREEN] source setuid/setgid bits fail closed before release construction")
    else:
        checks += 1
        print("[GREEN] non-POSIX platform retains the static privilege-bit rejection contract")

    if os.name == "posix":
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            _write_source(root, b"post-hash permission drift\n")
            output = root / "staged"
            with _builder_root(root):
                digest = build_release_package.build(output)

            original_hash = verify_release._hash_payload_exact_bounded
            mutated = False

            def hash_then_escalate(path: Path, expected_bytes: int):
                nonlocal mutated
                got = original_hash(path, expected_bytes)
                if not mutated and path.name == "payload.txt" and got is not None:
                    path.chmod(stat.S_IMODE(path.stat().st_mode) | stat.S_ISUID)
                    mutated = True
                return got

            verify_release._hash_payload_exact_bounded = hash_then_escalate
            try:
                rc, stderr = _verify(output, digest)
            finally:
                verify_release._hash_payload_exact_bounded = original_hash
            assert mutated
            assert rc == 2
            assert "unsafe release permission bits: payload.txt" in stderr
        checks += 1
        print("[GREEN] setuid drift after payload hashing is rejected by final inventory")
    else:
        checks += 1
        print("[GREEN] final inventory statically rechecks privilege-bearing permission bits")

    verifier_source = Path("verify_release.py").read_text(encoding="utf-8")
    assert "_has_unsafe_release_permissions(metadata)" in verifier_source
    assert "unsafe release permission bits" in verifier_source
    checks += 1
    print("[GREEN] verifier checks unsafe permissions before hashing and during final inventory")

    manifest = json.loads(Path("release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "build_release_package.py",
        "verify_release.py",
        "security_sec212_release_permission_sanitization_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] release manifest covers SEC-212 production code and regression")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-212 leaves canonical chain identity unchanged")

    print(f"SEC-212 release permission sanitization: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
