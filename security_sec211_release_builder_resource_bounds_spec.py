#!/usr/bin/env python3
"""SEC-211: release construction must have explicit resource budgets."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
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


def _manifest_bytes(files) -> bytes:
    return (json.dumps({"files": files}, indent=2) + "\n").encode("utf-8")


def _entry(data: bytes) -> dict:
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _expect_load_failure(root: Path, needle: str) -> None:
    with _builder_root(root):
        try:
            build_release_package._load_verified_sources()
        except RuntimeError as exc:
            assert needle in str(exc), (needle, str(exc))
        else:
            raise AssertionError(f"expected builder failure containing {needle!r}")


def main() -> None:
    checks = 0

    source = Path("build_release_package.py").read_text(encoding="utf-8")
    assert ".read_bytes()" not in source
    assert build_release_package.MAX_RELEASE_MANIFEST_BYTES == verify_release.MAX_RELEASE_MANIFEST_BYTES
    assert build_release_package.COPY_CHUNK_BYTES == 64 * 1024
    checks += 1
    print("[GREEN] builder uses bounded manifest IO and chunked payload copying instead of whole-file reads")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        (root / "release_manifest.json").write_bytes(
            b"x" * (build_release_package.MAX_RELEASE_MANIFEST_BYTES + 1)
        )
        _expect_load_failure(root, "verification budget")
    checks += 1
    print("[GREEN] oversized release manifest is rejected before JSON parsing")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        manifest = {
            "too-large.bin": {
                "bytes": build_release_package.MAX_RELEASE_FILE_BYTES + 1,
                "sha256": "0" * 64,
            }
        }
        (root / "release_manifest.json").write_bytes(_manifest_bytes(manifest))
        _expect_load_failure(root, "per-file budget")
    checks += 1
    print("[GREEN] authenticated metadata cannot request an over-budget single source file")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        manifest = {
            f"part-{index}.bin": {
                "bytes": build_release_package.MAX_RELEASE_FILE_BYTES,
                "sha256": "0" * 64,
            }
            for index in range(
                build_release_package.MAX_RELEASE_TOTAL_BYTES
                // build_release_package.MAX_RELEASE_FILE_BYTES
                + 1
            )
        }
        (root / "release_manifest.json").write_bytes(_manifest_bytes(manifest))
        _expect_load_failure(root, "aggregate budget")
    checks += 1
    print("[GREEN] aggregate release byte budget is enforced before payload IO")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        empty_hash = hashlib.sha256(b"").hexdigest()
        manifest = {
            f"f-{index:04d}.txt": {"bytes": 0, "sha256": empty_hash}
            for index in range(build_release_package.MAX_RELEASE_FILES + 1)
        }
        manifest_bytes = _manifest_bytes(manifest)
        assert len(manifest_bytes) <= build_release_package.MAX_RELEASE_MANIFEST_BYTES
        (root / "release_manifest.json").write_bytes(manifest_bytes)
        _expect_load_failure(root, "file verification budget")
    checks += 1
    print("[GREEN] manifest path-count budget prevents unbounded release fan-out")

    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        payload = b"bounded streaming release payload\n"
        (root / "payload.txt").write_bytes(payload)
        manifest_bytes = _manifest_bytes({"payload.txt": _entry(payload)})
        (root / "release_manifest.json").write_bytes(manifest_bytes)
        output = root / "staged"

        original_read_bytes = Path.read_bytes

        def forbidden_read_bytes(self):
            raise AssertionError(f"whole-file read_bytes is forbidden during SEC-211 build: {self}")

        Path.read_bytes = forbidden_read_bytes
        try:
            with _builder_root(root):
                digest = build_release_package.build(output)
        finally:
            Path.read_bytes = original_read_bytes

        assert digest == hashlib.sha256(manifest_bytes).hexdigest()
        assert (output / "payload.txt").read_bytes() == payload
    checks += 1
    print("[GREEN] a stable package builds and verifies while Path.read_bytes is disabled")

    manifest = json.loads(Path("release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "build_release_package.py",
        "security_sec211_release_builder_resource_bounds_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] release manifest covers the builder and SEC-211 regression")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-211 leaves canonical chain identity unchanged")

    print(f"SEC-211 release builder resource bounds: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
