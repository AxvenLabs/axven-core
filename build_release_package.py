#!/usr/bin/env python3
"""Build a clean Axven release directory from the authenticated manifest set."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import stat
import sys

import verify_release

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "release_manifest.json"

# SEC-211: release construction runs over a working tree that may be damaged or
# locally tampered with before it is trusted for publication. Keep manifest,
# path-count, per-file, aggregate IO, and memory costs explicitly bounded.
MAX_RELEASE_MANIFEST_BYTES = verify_release.MAX_RELEASE_MANIFEST_BYTES
MAX_RELEASE_FILES = 4096
MAX_RELEASE_FILE_BYTES = 64 * 1024 * 1024
MAX_RELEASE_TOTAL_BYTES = 256 * 1024 * 1024
COPY_CHUNK_BYTES = 64 * 1024


def _load_verified_sources():
    try:
        manifest_metadata = MANIFEST.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError("missing release_manifest.json") from exc
    if stat.S_ISLNK(manifest_metadata.st_mode) or not stat.S_ISREG(manifest_metadata.st_mode):
        raise RuntimeError("release_manifest.json must be a regular non-symlink file")

    try:
        manifest_bytes = verify_release._read_manifest_bounded(MANIFEST, manifest_metadata)
    except (OSError, ValueError) as exc:
        raise RuntimeError(str(exc)) from exc

    manifest = json.loads(manifest_bytes.decode("utf-8"))
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise RuntimeError("release manifest files must be a non-empty object")
    if len(files) > MAX_RELEASE_FILES:
        raise RuntimeError(
            f"release manifest exceeds {MAX_RELEASE_FILES} file verification budget"
        )

    bounded_entries = []
    total_bytes = 0
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
        if expected_bytes > MAX_RELEASE_FILE_BYTES:
            raise RuntimeError(
                f"manifest source exceeds {MAX_RELEASE_FILE_BYTES} byte per-file budget: {name}"
            )
        if total_bytes > MAX_RELEASE_TOTAL_BYTES - expected_bytes:
            raise RuntimeError(
                f"release manifest exceeds {MAX_RELEASE_TOTAL_BYTES} byte aggregate budget"
            )
        total_bytes += expected_bytes
        bounded_entries.append((name, pure, expected_hash.lower(), expected_bytes))

    sources = []
    root_resolved = ROOT.resolve()
    for name, pure, expected_hash, expected_bytes in bounded_entries:
        source = ROOT.joinpath(*pure.parts)
        resolved = source.resolve()
        try:
            resolved.relative_to(root_resolved)
        except ValueError as exc:
            raise RuntimeError(f"manifest source escapes release root: {name}") from exc

        try:
            metadata = source.lstat()
        except FileNotFoundError as exc:
            raise RuntimeError(f"missing manifest source: {name}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"manifest source is not a regular non-symlink file: {name}")
        if metadata.st_size != expected_bytes:
            raise RuntimeError(f"manifest source size mismatch: {name}")
        sources.append(
            (pure, source, expected_bytes, expected_hash, stat.S_IMODE(metadata.st_mode))
        )

    return manifest_bytes, sources


def _copy_verified_source(
    source: Path,
    destination: Path,
    expected_bytes: int,
    expected_hash: str,
) -> None:
    """Copy and authenticate one source with constant memory and bounded IO."""
    digest = hashlib.sha256()
    copied = 0

    with source.open("rb") as source_handle:
        opened_metadata = os.fstat(source_handle.fileno())
        if not stat.S_ISREG(opened_metadata.st_mode) or opened_metadata.st_size != expected_bytes:
            raise RuntimeError(f"manifest source size/type changed during build: {source.name}")

        with destination.open("xb") as destination_handle:
            while copied < expected_bytes:
                chunk = source_handle.read(min(COPY_CHUNK_BYTES, expected_bytes - copied))
                if not chunk:
                    break
                destination_handle.write(chunk)
                digest.update(chunk)
                copied += len(chunk)
            extra = source_handle.read(1)

    if copied != expected_bytes or extra:
        raise RuntimeError(f"manifest source size changed during build: {source.name}")
    if not hmac.compare_digest(digest.hexdigest(), expected_hash):
        raise RuntimeError(f"manifest source hash mismatch: {source.name}")


def build(output_dir: Path) -> str:
    output = Path(output_dir).expanduser().resolve()
    if output.exists():
        raise RuntimeError("release output directory must not already exist")

    manifest_bytes, sources = _load_verified_sources()
    output.mkdir(parents=True, exist_ok=False)
    try:
        for pure, source, expected_bytes, expected_hash, mode in sources:
            destination = output.joinpath(*pure.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            _copy_verified_source(source, destination, expected_bytes, expected_hash)
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
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"release build failed: {exc}", file=sys.stderr)
        return 2
    print(f"Release package directory: {Path(args[0]).expanduser().resolve()}")
    print(f"release_manifest.json SHA-256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
