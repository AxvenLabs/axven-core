#!/usr/bin/env python3
"""RUST-016: verify the staged repository-blind native source closure."""
from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import sys

ROOT = Path(__file__).resolve().parent
CANONICAL = {
    "Cargo.toml": ROOT / "native/axven_native/Cargo.toml",
    "Cargo.lock": ROOT / "native/axven_native/Cargo.lock",
    "src/lib.rs": ROOT / "native/axven_native/src/lib.rs",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: rust_016_source_closure_spec.py SOURCE_CLOSURE")
    closure = Path(sys.argv[1])
    if closure.is_symlink() or not closure.is_dir():
        raise AssertionError(f"source closure must be a real directory: {closure}")

    files: dict[str, Path] = {}
    for path in sorted(closure.rglob("*")):
        relative = path.relative_to(closure).as_posix()
        parts = PurePosixPath(relative).parts
        if any(part in {"", ".", ".."} for part in parts):
            raise AssertionError(f"unsafe closure path: {relative!r}")
        if path.is_symlink():
            raise AssertionError(f"source closure contains symlink: {relative}")
        if path.is_file():
            files[relative] = path
        elif not path.is_dir():
            raise AssertionError(f"unexpected source-closure object: {relative}")

    if frozenset(files) != frozenset(CANONICAL):
        raise AssertionError(f"unexpected source-closure path set: {sorted(files)!r}")

    checks = 0
    print(f"[GREEN] exact three-file native source closure: {sorted(files)!r}")
    checks += 1

    for relative, canonical in CANONICAL.items():
        if canonical.is_symlink() or not canonical.is_file():
            raise AssertionError(f"canonical native source must be a regular file: {relative}")
        staged = files[relative]
        canonical_sha = sha256(canonical)
        staged_sha = sha256(staged)
        if staged_sha != canonical_sha or staged.read_bytes() != canonical.read_bytes():
            raise AssertionError(
                f"staged native source mismatch: {relative} {staged_sha} != {canonical_sha}"
            )
    print("[GREEN] every staged source file is byte-identical to canonical native source")
    checks += 1

    if any(".git" in PurePosixPath(name).parts for name in files):
        raise AssertionError("source closure must not contain Git metadata")
    print("[GREEN] source closure contains no Git metadata, symlinks, or ambient repository files")
    checks += 1

    total_bytes = sum(path.stat().st_size for path in files.values())
    if total_bytes <= 0:
        raise AssertionError("empty native source closure")
    print(f"[GREEN] native source closure byte length is finite and non-empty: {total_bytes}")
    checks += 1

    if checks != 4:
        raise AssertionError(checks)
    print("RUST-016 exact native source closure contract: 4/4 GREEN")


if __name__ == "__main__":
    main()
