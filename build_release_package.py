#!/usr/bin/env python3
"""Build a clean Axven release directory from the authenticated manifest set."""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import shutil
import stat
import sys

import verify_release

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "release_manifest.json"


def _load_verified_sources():
    manifest_bytes = MANIFEST.read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise RuntimeError("release manifest files must be a non-empty object")

    sources = []
    root_resolved = ROOT.resolve()
    for name, meta in files.items():
        pure = verify_release._canonical_manifest_name(name)
        if pure is None or not isinstance(meta, dict):
            raise RuntimeError(f"invalid manifest entry: {name!r}")

        expected_hash = meta.get("sha256")
        expected_bytes = meta.get("bytes")
        if (
            verify_release.SHA256_RE.fullmatch(expected_hash or "") is None
            or type(expected_bytes) is not int
            or expected_bytes < 0
        ):
            raise RuntimeError(f"invalid manifest metadata: {name}")

        source = ROOT.joinpath(*pure.parts)
        resolved = source.resolve()
        try:
            resolved.relative_to(root_resolved)
        except ValueError as exc:
            raise RuntimeError(f"manifest source escapes release root: {name}") from exc

        metadata = source.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"manifest source is not a regular non-symlink file: {name}")
        data = source.read_bytes()
        if len(data) != expected_bytes:
            raise RuntimeError(f"manifest source size mismatch: {name}")
        got = hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(got, expected_hash.lower()):
            raise RuntimeError(f"manifest source hash mismatch: {name}")
        sources.append((pure, data, stat.S_IMODE(metadata.st_mode)))

    return manifest_bytes, sources


def build(output_dir: Path) -> str:
    output = Path(output_dir).expanduser().resolve()
    if output.exists():
        raise RuntimeError("release output directory must not already exist")

    manifest_bytes, sources = _load_verified_sources()
    output.mkdir(parents=True, exist_ok=False)
    try:
        for pure, data, mode in sources:
            destination = output.joinpath(*pure.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as handle:
                handle.write(data)
            try:
                destination.chmod(mode)
            except OSError:
                # Windows filesystems may not preserve POSIX mode bits; content
                # authenticity remains enforced by the manifest.
                pass

        staged_manifest = output / "release_manifest.json"
        with staged_manifest.open("xb") as handle:
            handle.write(manifest_bytes)

        digest = hashlib.sha256(manifest_bytes).hexdigest()
        original_root = verify_release.ROOT
        original_manifest = verify_release.MANIFEST
        verify_release.ROOT = output
        verify_release.MANIFEST = staged_manifest
        try:
            if verify_release.main([digest]) != 0:
                raise RuntimeError("staged release failed exact-inventory verification")
        finally:
            verify_release.ROOT = original_root
            verify_release.MANIFEST = original_manifest
        return digest
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python build_release_package.py <new-output-directory>", file=sys.stderr)
        return 2
    try:
        digest = build(Path(args[0]))
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"release build failed: {exc}", file=sys.stderr)
        return 2
    print(f"Release package directory: {Path(args[0]).expanduser().resolve()}")
    print(f"release_manifest.json SHA-256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
