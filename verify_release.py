#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path, PurePosixPath
import hashlib
import hmac
import json
import re
import stat
import sys

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "release_manifest.json"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


def _canonical_manifest_name(name: str) -> PurePosixPath | None:
    if type(name) is not str or not name or "\\" in name:
        return None
    pure = PurePosixPath(name)
    if pure.is_absolute() or pure.as_posix() != name:
        return None
    if any(part in ("", ".", "..") for part in pure.parts):
        return None
    return pure


def _release_inventory_violations(root: Path, manifest_names) -> list[str]:
    """Require an exact staged release inventory.

    SEC-207 deliberately does not try to classify unmanifested files as
    "probably inert".  A verified release asset is built from the authenticated
    manifest, so every file/symlink/special entry other than the manifest itself
    must be represented by an authenticated manifest entry.
    """
    root = root.resolve()
    expected = set(manifest_names)
    expected.add("release_manifest.json")
    bad: list[str] = []

    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            bad.append(f"release path changed during inventory: {relative}")
            continue

        if stat.S_ISDIR(metadata.st_mode):
            continue
        if relative not in expected:
            if stat.S_ISLNK(metadata.st_mode):
                bad.append(f"unexpected release symlink: {relative}")
            elif stat.S_ISREG(metadata.st_mode):
                bad.append(f"unexpected unmanifested release file: {relative}")
            else:
                bad.append(f"unexpected release special file: {relative}")

    return sorted(bad)


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or SHA256_RE.fullmatch(args[0]) is None:
        return fail(
            "usage: python verify_release.py <trusted-release_manifest.json-sha256>\n"
            "The SHA-256 trust anchor must be obtained outside the downloaded release package."
        )

    try:
        manifest_metadata = MANIFEST.lstat()
    except FileNotFoundError:
        return fail("missing release_manifest.json")
    if stat.S_ISLNK(manifest_metadata.st_mode) or not stat.S_ISREG(manifest_metadata.st_mode):
        return fail("release_manifest.json must be a regular non-symlink file")

    expected_manifest_sha256 = args[0].lower()
    manifest_bytes = MANIFEST.read_bytes()
    actual_manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if not hmac.compare_digest(actual_manifest_sha256, expected_manifest_sha256):
        return fail(
            "release manifest trust-anchor mismatch: "
            f"expected {expected_manifest_sha256}, got {actual_manifest_sha256}"
        )

    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return fail(f"invalid release manifest: {exc}")

    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        return fail("invalid release manifest: files must be a non-empty object")

    bad = []
    checked = 0
    canonical_names = set()
    root_resolved = ROOT.resolve()
    for name, meta in files.items():
        pure = _canonical_manifest_name(name)
        if pure is None or not isinstance(meta, dict):
            bad.append(f"invalid manifest entry: {name!r}")
            continue
        if name in canonical_names:
            bad.append(f"duplicate manifest path: {name}")
            continue
        canonical_names.add(name)

        expected_hash = meta.get("sha256")
        expected_bytes = meta.get("bytes")
        if SHA256_RE.fullmatch(expected_hash or "") is None or type(expected_bytes) is not int or expected_bytes < 0:
            bad.append(f"invalid manifest metadata: {name}")
            continue

        candidate = ROOT.joinpath(*pure.parts)
        resolved = candidate.resolve()
        try:
            resolved.relative_to(root_resolved)
        except ValueError:
            bad.append(f"path escapes release root: {name}")
            continue
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            bad.append(f"missing or non-file: {name}")
            continue
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            bad.append(f"missing or non-regular file: {name}")
            continue

        data = candidate.read_bytes()
        checked += 1
        if len(data) != expected_bytes:
            bad.append(f"size mismatch: {name}")
            continue
        got = hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(got, expected_hash.lower()):
            bad.append(f"hash mismatch: {name}")

    if not bad:
        bad.extend(_release_inventory_violations(ROOT, canonical_names))

    if bad:
        print("\n".join(bad), file=sys.stderr)
        return 2

    print(f"Release trust anchor: {actual_manifest_sha256}")
    print(f"Release integrity: {checked}/{checked} GREEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
