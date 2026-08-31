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

# A source checkout contains inert repository metadata and may contain local
# interpreter/build metadata by the time a developer runs verification.  Those
# paths are not release-executable payload.  Everything else must either be
# authenticated by the manifest or be inert documentation.
_INERT_UNMANIFESTED_EXACT = frozenset({".gitattributes", ".gitignore"})
_INERT_UNMANIFESTED_SUFFIXES = frozenset({".md"})
_IGNORED_LOCAL_DIR_NAMES = frozenset({".git", "__pycache__", ".pytest_cache"})


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


def _is_ignored_local_path(relative: str) -> bool:
    parts = PurePosixPath(relative).parts
    return any(
        part in _IGNORED_LOCAL_DIR_NAMES or part.endswith(".egg-info")
        for part in parts
    )


def _is_inert_unmanifested_path(relative: str) -> bool:
    if relative in _INERT_UNMANIFESTED_EXACT:
        return True
    if relative.startswith(".github/"):
        return True
    return PurePosixPath(relative).suffix.lower() in _INERT_UNMANIFESTED_SUFFIXES


def _unexpected_release_payloads(root: Path, manifest_names) -> list[str]:
    """Return unmanifested active/special payloads under a release root.

    The manifest is an allow-list for executable/runtime data.  Repository
    documentation may remain outside that list, but an attacker must not be
    able to append a Python module, launcher, binary, runtime JSON/config, venv,
    or filesystem indirection while preserving every authenticated manifest
    hash.
    """
    root = root.resolve()
    expected = set(manifest_names)
    bad: list[str] = []

    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if relative == "release_manifest.json" or relative in expected:
            continue
        if _is_ignored_local_path(relative):
            continue

        try:
            metadata = path.lstat()
        except FileNotFoundError:
            bad.append(f"release path changed during inventory: {relative}")
            continue

        # Never allow an unmanifested symlink/special file, even under an
        # otherwise inert documentation/SCM path.
        if stat.S_ISLNK(metadata.st_mode):
            bad.append(f"unexpected release symlink: {relative}")
            continue
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            bad.append(f"unexpected release special file: {relative}")
            continue
        if _is_inert_unmanifested_path(relative):
            continue
        bad.append(f"unexpected unmanifested release payload: {relative}")

    return sorted(bad)


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or SHA256_RE.fullmatch(args[0]) is None:
        return fail(
            "usage: python verify_release.py <trusted-release_manifest.json-sha256>\n"
            "The SHA-256 trust anchor must be obtained outside the downloaded release package."
        )

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
            resolved.relative_to(ROOT.resolve())
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
        bad.extend(_unexpected_release_payloads(ROOT, canonical_names))

    if bad:
        print("\n".join(bad), file=sys.stderr)
        return 2

    print(f"Release trust anchor: {actual_manifest_sha256}")
    print(f"Release integrity: {checked}/{checked} GREEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
