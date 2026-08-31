#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import hashlib
import hmac
import json
import re
import sys

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "release_manifest.json"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


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
    for name, meta in files.items():
        if not isinstance(name, str) or not isinstance(meta, dict):
            bad.append(f"invalid manifest entry: {name!r}")
            continue
        expected_hash = meta.get("sha256")
        expected_bytes = meta.get("bytes")
        if SHA256_RE.fullmatch(expected_hash or "") is None or type(expected_bytes) is not int or expected_bytes < 0:
            bad.append(f"invalid manifest metadata: {name}")
            continue

        path = (ROOT / name).resolve()
        try:
            path.relative_to(ROOT)
        except ValueError:
            bad.append(f"path escapes release root: {name}")
            continue
        if not path.is_file():
            bad.append(f"missing or non-file: {name}")
            continue

        data = path.read_bytes()
        checked += 1
        if len(data) != expected_bytes:
            bad.append(f"size mismatch: {name}")
            continue
        got = hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(got, expected_hash.lower()):
            bad.append(f"hash mismatch: {name}")

    if bad:
        print("\n".join(bad), file=sys.stderr)
        return 2

    print(f"Release trust anchor: {actual_manifest_sha256}")
    print(f"Release integrity: {checked}/{checked} GREEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
