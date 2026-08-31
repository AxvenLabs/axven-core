#!/usr/bin/env python3
"""SEC-212: staged releases must not inherit unsafe working-tree mode bits."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory

import axven
import build_release_package


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


def _entry(data: bytes) -> dict:
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _manifest_bytes(files) -> bytes:
    return (json.dumps({"files": files}, indent=2) + "\n").encode("utf-8")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def main() -> None:
    checks = 0

    source = Path("build_release_package.py").read_text(encoding="utf-8")
    assert build_release_package.SAFE_RELEASE_FILE_MODE == 0o644
    assert build_release_package.SAFE_RELEASE_DIR_MODE == 0o755
    assert "stat.S_IMODE(metadata.st_mode)" not in source
    assert "_normalize_staged_permissions(output)" in source
    checks += 1
    print("[GREEN] builder uses deterministic release modes instead of copying source mode metadata")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        source_dir = root / "nested"
        source_dir.mkdir()
        payload = source_dir / "payload.txt"
        payload_bytes = b"authenticated payload with unauthenticated source mode\n"
        payload.write_bytes(payload_bytes)
        manifest_bytes = _manifest_bytes({"nested/payload.txt": _entry(payload_bytes)})
        manifest = root / "release_manifest.json"
        manifest.write_bytes(manifest_bytes)

        if os.name != "nt":
            source_dir.chmod(0o777)
            payload.chmod(0o6777)
            manifest.chmod(0o666)
            assert _mode(payload) & 0o022

        output = root / "staged"
        previous_umask = os.umask(0)
        try:
            with _builder_root(root):
                digest = build_release_package.build(output)
        finally:
            os.umask(previous_umask)

        assert digest == hashlib.sha256(manifest_bytes).hexdigest()
        assert (output / "nested" / "payload.txt").read_bytes() == payload_bytes

        if os.name != "nt":
            assert _mode(output) == 0o755, oct(_mode(output))
            assert _mode(output / "nested") == 0o755, oct(_mode(output / "nested"))
            assert _mode(output / "nested" / "payload.txt") == 0o644, oct(
                _mode(output / "nested" / "payload.txt")
            )
            assert _mode(output / "release_manifest.json") == 0o644, oct(
                _mode(output / "release_manifest.json")
            )
    checks += 1
    print("[GREEN] unsafe source chmod and permissive umask cannot escape into the staged release")

    with TemporaryDirectory() as tmp:
        output = Path(tmp).resolve() / "staged"
        output.mkdir()
        regular = output / "regular.txt"
        regular.write_text("x", encoding="utf-8")
        if os.name != "nt":
            regular.chmod(0o777)
            link = output / "unexpected-link"
            link.symlink_to(regular.name)
            try:
                build_release_package._normalize_staged_permissions(output)
            except RuntimeError as exc:
                assert "unexpected symlink" in str(exc)
            else:
                raise AssertionError("staged permission normalization accepted a symlink")
    checks += 1
    print("[GREEN] permission normalization fails closed if a staged symlink appears")

    manifest_data = json.loads(Path("release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "build_release_package.py",
        "security_sec212_release_mode_sanitization_spec.py",
    ):
        assert name in manifest_data["files"], name
    checks += 1
    print("[GREEN] release manifest covers the builder and SEC-212 regression")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-212 leaves canonical chain identity unchanged")

    print(f"SEC-212 release mode sanitization: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
