#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path, PurePosixPath
import hashlib
import hmac
import json
import os
import re
import stat
import sys

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "release_manifest.json"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# SEC-209: the verifier runs on attacker-supplied downloaded bytes before those
# bytes are trusted.  Keep memory use independent of archive-controlled file
# sizes.  The authenticated manifest then supplies the exact byte budget for
# each listed payload file.
MAX_RELEASE_MANIFEST_BYTES = 1024 * 1024
HASH_CHUNK_BYTES = 64 * 1024

# SEC-212: file content hashes do not authenticate filesystem metadata.  Never
# accept privilege-bearing POSIX permission bits on release payloads or the
# manifest, and repeat this check during the final inventory sweep so a mode
# change after hashing also fails closed.
UNSAFE_RELEASE_PERMISSION_BITS = stat.S_ISUID | stat.S_ISGID


class _VerifiedBytes(bytes):
    """Bytes bound to the descriptor identity that supplied them."""
    def __new__(cls, data: bytes, metadata):
        obj = bytes.__new__(cls, data)
        obj._verified_metadata = metadata
        return obj


class _VerifiedDigest(str):
    """Hex digest bound to the descriptor identity that was hashed."""
    def __new__(cls, digest: str, metadata):
        obj = str.__new__(cls, digest)
        obj._verified_metadata = metadata
        return obj


def _same_file(before, opened) -> bool:
    """Return True only when two stat snapshots identify one file object."""
    try:
        return os.path.samestat(before, opened)
    except (AttributeError, OSError):
        return (before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino)


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


def _has_unsafe_release_permissions(metadata) -> bool:
    return bool(metadata.st_mode & UNSAFE_RELEASE_PERMISSION_BITS)


def _read_manifest_bounded(path: Path, metadata) -> bytes:
    if metadata.st_size > MAX_RELEASE_MANIFEST_BYTES:
        raise ValueError(
            "release_manifest.json exceeds "
            f"{MAX_RELEASE_MANIFEST_BYTES} byte verification budget"
        )
    try:
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or not _same_file(metadata, opened)
                or opened.st_size != metadata.st_size
                or _has_unsafe_release_permissions(opened)
            ):
                raise ValueError("release_manifest.json changed before reading")
            data = handle.read(MAX_RELEASE_MANIFEST_BYTES + 1)
            finished = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(finished.st_mode)
                or not _same_file(opened, finished)
                or finished.st_size != opened.st_size
                or _has_unsafe_release_permissions(finished)
            ):
                raise ValueError("release_manifest.json changed while reading")
    except ValueError:
        raise
    except OSError:
        raise
    if len(data) > MAX_RELEASE_MANIFEST_BYTES:
        raise ValueError(
            "release_manifest.json exceeds "
            f"{MAX_RELEASE_MANIFEST_BYTES} byte verification budget"
        )
    try:
        after = path.lstat()
    except OSError as exc:
        raise ValueError("release_manifest.json changed after reading") from exc
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or not _same_file(opened, after)
        or after.st_size != opened.st_size
        or _has_unsafe_release_permissions(after)
    ):
        raise ValueError("release_manifest.json changed after reading")
    return _VerifiedBytes(data, opened)


def _hash_payload_exact_bounded(path: Path, expected_bytes: int) -> str | None:
    """Hash exact authenticated bytes while binding the read to one file object."""
    try:
        before = path.lstat()
    except OSError:
        raise
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError("release payload changed before hashing")
    if _has_unsafe_release_permissions(before):
        raise ValueError("unsafe release permission bits during hashing")
    if before.st_size != expected_bytes:
        return None

    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or not _same_file(before, opened)
            or opened.st_size != expected_bytes
        ):
            raise ValueError("release payload changed before hashing")
        if _has_unsafe_release_permissions(opened):
            raise ValueError("unsafe release permission bits during hashing")

        while total < expected_bytes:
            chunk = handle.read(min(HASH_CHUNK_BYTES, expected_bytes - total))
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
        extra = handle.read(1)

        finished = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(finished.st_mode)
            or not _same_file(opened, finished)
            or finished.st_size != expected_bytes
        ):
            raise ValueError("release payload changed while hashing")
        if _has_unsafe_release_permissions(finished):
            raise ValueError("unsafe release permission bits during hashing")

    if total != expected_bytes or extra:
        return None

    try:
        after = path.lstat()
    except OSError as exc:
        raise ValueError("release payload changed after hashing") from exc
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or not _same_file(opened, after)
        or after.st_size != expected_bytes
    ):
        raise ValueError("release payload changed after hashing")
    if _has_unsafe_release_permissions(after):
        raise ValueError("unsafe release permission bits after hashing")
    return _VerifiedDigest(digest.hexdigest(), opened)


def _release_inventory_violations(
    root: Path, manifest_names, verified_files=None
) -> list[str]:
    """Require exact inventory plus final authenticated expected-file state.

    SEC-207 rejects every unmanifested file/symlink/special entry. SEC-210 also
    requires every authenticated expected path to remain present as a regular,
    non-symlink file through the final inventory sweep. SEC-212 additionally
    rejects privilege-bearing permission bits both before and after hashing.
    SEC-221 re-authenticates every expected regular file in the final sweep and
    compares its descriptor identity with the first authenticated read, closing
    same-size replacement and in-place content drift between the two phases.
    """
    root = root.resolve()
    expected = set(manifest_names)
    expected.add("release_manifest.json")
    seen_expected: set[str] = set()
    stable_expected: set[str] = set()
    bad: list[str] = []

    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if relative in expected:
                bad.append(f"missing verified release file after hashing: {relative}")
            else:
                bad.append(f"release path changed during inventory: {relative}")
            continue

        if relative in expected:
            seen_expected.add(relative)
            if stat.S_ISLNK(metadata.st_mode):
                bad.append(f"expected release file became symlink: {relative}")
            elif stat.S_ISREG(metadata.st_mode):
                if _has_unsafe_release_permissions(metadata):
                    bad.append(f"unsafe release permission bits: {relative}")
                else:
                    stable_expected.add(relative)
            elif stat.S_ISDIR(metadata.st_mode):
                bad.append(f"expected release file became directory: {relative}")
            else:
                bad.append(f"expected release file became special file: {relative}")
            continue

        if stat.S_ISDIR(metadata.st_mode):
            continue
        if stat.S_ISLNK(metadata.st_mode):
            bad.append(f"unexpected release symlink: {relative}")
        elif stat.S_ISREG(metadata.st_mode):
            bad.append(f"unexpected unmanifested release file: {relative}")
        else:
            bad.append(f"unexpected release special file: {relative}")

    for relative in sorted(expected - seen_expected):
        bad.append(f"missing verified release file after hashing: {relative}")

    if verified_files is not None:
        for relative in sorted(stable_expected):
            record = verified_files.get(relative)
            if record is None:
                bad.append(f"verified release file identity unavailable: {relative}")
                continue
            expected_bytes, expected_hash, first_metadata = record
            path = root.joinpath(*PurePosixPath(relative).parts)
            try:
                got = _hash_payload_exact_bounded(path, expected_bytes)
            except (OSError, ValueError):
                bad.append(
                    f"verified release file changed during final authentication: {relative}"
                )
                continue
            if got is None:
                bad.append(f"verified release file size changed after hashing: {relative}")
                continue
            if not hmac.compare_digest(got, expected_hash):
                bad.append(f"verified release file content changed after hashing: {relative}")
                continue
            final_metadata = getattr(got, "_verified_metadata", None)
            if (
                first_metadata is None
                or final_metadata is None
                or not _same_file(first_metadata, final_metadata)
            ):
                bad.append(f"verified release file identity changed after hashing: {relative}")

    return sorted(set(bad))


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
    if _has_unsafe_release_permissions(manifest_metadata):
        return fail("unsafe release permission bits: release_manifest.json")

    try:
        manifest_bytes = _read_manifest_bounded(MANIFEST, manifest_metadata)
    except (OSError, ValueError) as exc:
        return fail(str(exc))

    expected_manifest_sha256 = args[0].lower()
    actual_manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if not hmac.compare_digest(actual_manifest_sha256, expected_manifest_sha256):
        return fail(
            "release manifest trust-anchor mismatch: "
            f"expected {expected_manifest_sha256}, got {actual_manifest_sha256}"
        )

    manifest_verified_metadata = getattr(manifest_bytes, "_verified_metadata", None)
    if manifest_verified_metadata is None:
        return fail("release manifest verification identity unavailable")

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
    verified_files = {
        "release_manifest.json": (
            len(manifest_bytes),
            expected_manifest_sha256,
            manifest_verified_metadata,
        )
    }
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
        expected_hash = expected_hash.lower()

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
        if _has_unsafe_release_permissions(metadata):
            bad.append(f"unsafe release permission bits: {name}")
            continue

        # The trusted manifest's exact size is the IO-work budget. Reject an
        # obvious oversized replacement before opening it, then stream at most
        # that many bytes plus one byte while binding the read to one descriptor.
        if metadata.st_size != expected_bytes:
            bad.append(f"size mismatch: {name}")
            continue
        try:
            got = _hash_payload_exact_bounded(candidate, expected_bytes)
        except OSError:
            bad.append(f"unreadable file: {name}")
            continue
        except ValueError as exc:
            bad.append(f"{exc}: {name}")
            continue
        checked += 1
        if got is None:
            bad.append(f"size mismatch: {name}")
            continue
        if not hmac.compare_digest(got, expected_hash):
            bad.append(f"hash mismatch: {name}")
            continue
        verified_metadata = getattr(got, "_verified_metadata", None)
        if verified_metadata is None:
            bad.append(f"release payload verification identity unavailable: {name}")
            continue
        verified_files[name] = (
            expected_bytes,
            expected_hash,
            verified_metadata,
        )

    if not bad:
        bad.extend(
            _release_inventory_violations(
                ROOT,
                canonical_names,
                verified_files=verified_files,
            )
        )

    if bad:
        print("\n".join(bad), file=sys.stderr)
        return 2

    print(f"Release trust anchor: {actual_manifest_sha256}")
    print(f"Release integrity: {checked}/{checked} GREEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
