#!/usr/bin/env python3
"""RUST-018: detached authenticated native-source closure and rebuild verifier."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import sys
import tempfile
import zipfile

# Detached verification must not mutate its own evidence tree with Python bytecode.
sys.dont_write_bytecode = True

import rust_015_offline_repro_consumer_verify as evidence
import rust_016_offline_build_input_verify as sourcecheck
import rust_017_offline_git_tree_verify as gitcheck

REBUILD_SOURCE_KEYS = frozenset(
    {
        "native/axven_native/Cargo.toml",
        "native/axven_native/Cargo.lock",
        "native/axven_native/src/lib.rs",
        "native/axven_native/pyproject.toml",
        "native/axven_native/rust-toolchain.toml",
    }
)
LEGACY_SIGNED_NATIVE_KEYS = frozenset(
    {
        "native/axven_native/Cargo.toml",
        "native/axven_native/Cargo.lock",
        "native/axven_native/src/lib.rs",
    }
)
COMMIT_AUTHENTICATED_CONFIG_KEYS = frozenset(
    {
        "native/axven_native/pyproject.toml",
        "native/axven_native/rust-toolchain.toml",
    }
)
EXPECTED_WHEEL = evidence.WHEEL_FILENAME
HEX = frozenset("0123456789abcdef")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _assert_regular_file(path: Path, label: str) -> None:
    if path.is_symlink():
        raise AssertionError(f"{label} must not be a symlink")
    if not path.is_file():
        raise AssertionError(f"{label} must be a regular file")


def _assert_real_directory(path: Path, label: str) -> None:
    if path.is_symlink():
        raise AssertionError(f"{label} must not be a symlink")
    if not path.is_dir():
        raise AssertionError(f"{label} must be a real directory")


def _allowed_directories() -> frozenset[str]:
    result: set[str] = set()
    for name in REBUILD_SOURCE_KEYS:
        parent = PurePosixPath(name).parent
        while parent.parts:
            result.add(parent.as_posix())
            parent = parent.parent
    return frozenset(result)


ALLOWED_DIRECTORIES = _allowed_directories()


def _validate_exact_rebuild_tree(root: Path) -> None:
    _assert_real_directory(root, "detached rebuild source root")
    files: set[str] = set()
    directories: set[str] = set()
    for entry in root.rglob("*"):
        relative = entry.relative_to(root).as_posix()
        if entry.is_symlink():
            raise AssertionError(f"detached rebuild source contains symlink: {relative}")
        if entry.is_dir():
            if relative not in ALLOWED_DIRECTORIES:
                raise AssertionError(f"unexpected detached rebuild directory: {relative}")
            directories.add(relative)
            continue
        if not entry.is_file():
            raise AssertionError(f"unsupported rebuild source filesystem object: {relative}")
        if relative not in REBUILD_SOURCE_KEYS:
            raise AssertionError(f"unexpected detached rebuild source file: {relative}")
        files.add(relative)
    if files != set(REBUILD_SOURCE_KEYS):
        raise AssertionError(
            f"detached rebuild source path set mismatch: missing={sorted(set(REBUILD_SOURCE_KEYS)-files)!r} "
            f"extra={sorted(files-set(REBUILD_SOURCE_KEYS))!r}"
        )
    if directories != set(ALLOWED_DIRECTORIES):
        raise AssertionError(
            f"detached rebuild directory set mismatch: {sorted(directories)!r}"
        )


def _git_child_for_path(
    root_tree_oid: str,
    trees: dict[str, dict[bytes, tuple[str, str]]],
    relative: str,
) -> tuple[str, str]:
    current_tree = root_tree_oid
    components = PurePosixPath(relative).parts
    for index, component in enumerate(components):
        entries = trees.get(current_tree)
        if entries is None:
            raise AssertionError(
                f"missing detached Git tree while walking rebuild path {relative}: {current_tree}"
            )
        key = component.encode("utf-8")
        if key not in entries:
            raise AssertionError(f"signed Git commit does not contain rebuild path: {relative}")
        mode, child_oid = entries[key]
        terminal = index == len(components) - 1
        if terminal:
            return mode, child_oid
        if mode != gitcheck.TREE_MODE:
            raise AssertionError(
                f"non-tree intermediate component for rebuild path {relative}: {component} mode={mode}"
            )
        current_tree = child_oid
    raise AssertionError(f"empty rebuild path: {relative}")


def _verify_source_closure(
    provenance: dict,
    signed_source_root: Path,
    git_root: Path,
    rebuild_source_root: Path,
) -> tuple[str, str]:
    _validate_exact_rebuild_tree(rebuild_source_root)

    for relative in sorted(LEGACY_SIGNED_NATIVE_KEYS):
        signed = signed_source_root.joinpath(*PurePosixPath(relative).parts)
        rebuilt = rebuild_source_root.joinpath(*PurePosixPath(relative).parts)
        _assert_regular_file(signed, f"RUST-016 signed native input {relative}")
        _assert_regular_file(rebuilt, f"detached rebuild native input {relative}")
        if rebuilt.read_bytes() != signed.read_bytes():
            raise AssertionError(f"detached rebuild source diverges from RUST-016 signed bytes: {relative}")

    commit_payload, trees = gitcheck._load_git_objects(git_root)
    source_commit = provenance["source"]["commit"]
    if gitcheck._git_oid("commit", commit_payload) != source_commit:
        raise AssertionError("detached Git commit object no longer matches signed source.commit")
    root_tree_oid, committer_epoch = gitcheck._parse_commit(commit_payload)
    if committer_epoch != provenance["source_date_epoch"]:
        raise AssertionError("detached Git commit epoch disagrees with signed source_date_epoch")
    if root_tree_oid not in trees:
        raise AssertionError("detached Git object set lacks signed commit root tree")

    for relative in sorted(REBUILD_SOURCE_KEYS):
        mode, expected_blob = _git_child_for_path(root_tree_oid, trees, relative)
        if mode not in gitcheck.REGULAR_FILE_MODES:
            raise AssertionError(f"rebuild source path is not a regular Git blob: {relative} mode={mode}")
        path = rebuild_source_root.joinpath(*PurePosixPath(relative).parts)
        _assert_regular_file(path, f"authenticated rebuild source {relative}")
        actual_blob = gitcheck._git_oid("blob", path.read_bytes())
        if actual_blob != expected_blob:
            raise AssertionError(f"Git blob membership mismatch for rebuild source: {relative}")

    legacy_keys = frozenset(provenance["build_inputs"])
    if not LEGACY_SIGNED_NATIVE_KEYS.issubset(legacy_keys):
        raise AssertionError("legacy signed provenance lost required native source keys")
    if COMMIT_AUTHENTICATED_CONFIG_KEYS & legacy_keys:
        raise AssertionError("RUST-018 legacy-closure assumption drifted; update the policy instead of silently accepting it")

    return source_commit, root_tree_oid


def _sourcecheck(
    wheel_a: Path,
    wheel_b: Path,
    provenance_path: Path,
    envelope_path: Path,
    signed_source_root: Path,
    git_root: Path,
    rebuild_source_root: Path,
) -> tuple[str, str, dict]:
    artifact_sha, source_commit = gitcheck._verify(
        wheel_a,
        wheel_b,
        provenance_path,
        envelope_path,
        signed_source_root,
        git_root,
    )
    _, provenance = evidence._load_canonical_json(
        provenance_path, label="reproducibility provenance"
    )
    closure_commit, _root_tree = _verify_source_closure(
        provenance, signed_source_root, git_root, rebuild_source_root
    )
    if closure_commit != source_commit:
        raise AssertionError("RUST-018 source closure commit disagrees with RUST-017")
    return artifact_sha, source_commit, provenance


def sourcecheck_only(
    wheel_a: Path,
    wheel_b: Path,
    provenance_path: Path,
    envelope_path: Path,
    signed_source_root: Path,
    git_root: Path,
    rebuild_source_root: Path,
) -> None:
    artifact_sha, source_commit, _provenance = _sourcecheck(
        wheel_a,
        wheel_b,
        provenance_path,
        envelope_path,
        signed_source_root,
        git_root,
        rebuild_source_root,
    )
    print(
        "RUST-018 detached authenticated rebuild source: GREEN "
        f"artifact_sha256={artifact_sha} source={source_commit} files={len(REBUILD_SOURCE_KEYS)}"
    )


def _actual_wheel(path: Path, label: str) -> dict[str, object]:
    _assert_regular_file(path, label)
    if path.name != EXPECTED_WHEEL:
        raise AssertionError(f"{label} filename/path binding mismatch: {path.name}")
    size = path.stat().st_size
    if size <= 0:
        raise AssertionError(f"{label} is empty")
    return {"sha256": _sha256_file(path), "bytes": size}


def _verify(
    wheel_a: Path,
    wheel_b: Path,
    provenance_path: Path,
    envelope_path: Path,
    signed_source_root: Path,
    git_root: Path,
    rebuild_source_root: Path,
    rebuilt_wheel: Path,
) -> tuple[str, str]:
    artifact_sha, source_commit, provenance = _sourcecheck(
        wheel_a,
        wheel_b,
        provenance_path,
        envelope_path,
        signed_source_root,
        git_root,
        rebuild_source_root,
    )
    actual = _actual_wheel(rebuilt_wheel, "detached rebuilt wheel")
    expected = {
        "sha256": provenance["artifact"]["sha256"],
        "bytes": provenance["artifact"]["bytes"],
    }
    if actual != expected:
        raise AssertionError(f"detached rebuilt wheel does not match signed artifact claim: {actual!r} != {expected!r}")
    if actual["sha256"] != artifact_sha:
        raise AssertionError("detached rebuilt wheel disagrees with upstream artifact digest")
    if rebuilt_wheel.read_bytes() != wheel_a.read_bytes() or rebuilt_wheel.read_bytes() != wheel_b.read_bytes():
        raise AssertionError("detached rebuilt wheel is not byte-for-byte identical to builds A and B")
    evidence._validate_wheel_zip(rebuilt_wheel, provenance["source_date_epoch"])
    return artifact_sha, source_commit


def verify(
    wheel_a: Path,
    wheel_b: Path,
    provenance_path: Path,
    envelope_path: Path,
    signed_source_root: Path,
    git_root: Path,
    rebuild_source_root: Path,
    rebuilt_wheel: Path,
) -> None:
    artifact_sha, source_commit = _verify(
        wheel_a,
        wheel_b,
        provenance_path,
        envelope_path,
        signed_source_root,
        git_root,
        rebuild_source_root,
        rebuilt_wheel,
    )
    print(
        "RUST-018 detached network-disabled rebuild equivalence: GREEN "
        f"artifact_sha256={artifact_sha} source={source_commit}"
    )


def _must_reject_source(
    wheel_a: Path,
    wheel_b: Path,
    provenance_path: Path,
    envelope_path: Path,
    signed_source_root: Path,
    git_root: Path,
    rebuild_source_root: Path,
    label: str,
) -> None:
    try:
        _sourcecheck(
            wheel_a,
            wheel_b,
            provenance_path,
            envelope_path,
            signed_source_root,
            git_root,
            rebuild_source_root,
        )
    except (AssertionError, json.JSONDecodeError, UnicodeDecodeError, OSError, zipfile.BadZipFile):
        print(f"[GREEN] rejected {label}")
        return
    raise AssertionError(f"RUST-018 source mutation unexpectedly accepted: {label}")


def _must_reject_full(
    wheel_a: Path,
    wheel_b: Path,
    provenance_path: Path,
    envelope_path: Path,
    signed_source_root: Path,
    git_root: Path,
    rebuild_source_root: Path,
    rebuilt_wheel: Path,
    label: str,
) -> None:
    try:
        _verify(
            wheel_a,
            wheel_b,
            provenance_path,
            envelope_path,
            signed_source_root,
            git_root,
            rebuild_source_root,
            rebuilt_wheel,
        )
    except (AssertionError, json.JSONDecodeError, UnicodeDecodeError, OSError, zipfile.BadZipFile):
        print(f"[GREEN] rejected {label}")
        return
    raise AssertionError(f"RUST-018 rebuild mutation unexpectedly accepted: {label}")


def _copy_source(root: Path, destination: Path) -> Path:
    shutil.copytree(root, destination)
    return destination


def _snapshot(root: Path) -> dict[str, str]:
    return {
        name: _sha256_file(root.joinpath(*PurePosixPath(name).parts))
        for name in sorted(REBUILD_SOURCE_KEYS)
    }


def selftest(
    wheel_a: Path,
    wheel_b: Path,
    provenance_path: Path,
    envelope_path: Path,
    signed_source_root: Path,
    git_root: Path,
    rebuild_source_root: Path,
    rebuilt_wheel: Path,
) -> None:
    verify(
        wheel_a,
        wheel_b,
        provenance_path,
        envelope_path,
        signed_source_root,
        git_root,
        rebuild_source_root,
        rebuilt_wheel,
    )
    wheel_sha_before = _sha256_file(rebuilt_wheel)
    source_before = _snapshot(rebuild_source_root)
    checks = 0

    with tempfile.TemporaryDirectory(prefix="axven-rust018-") as temp:
        root = Path(temp)

        for relative, label in (
            ("native/axven_native/pyproject.toml", "native pyproject byte mutation"),
            ("native/axven_native/rust-toolchain.toml", "Rust toolchain file byte mutation"),
            ("native/axven_native/Cargo.toml", "legacy signed Cargo manifest divergence"),
        ):
            mutated = _copy_source(rebuild_source_root, root / f"mutated-{checks}")
            target = mutated.joinpath(*PurePosixPath(relative).parts)
            target.write_bytes(target.read_bytes() + b"\x00")
            _must_reject_source(
                wheel_a, wheel_b, provenance_path, envelope_path,
                signed_source_root, git_root, mutated, label,
            )
            checks += 1

        missing = _copy_source(rebuild_source_root, root / "missing")
        missing.joinpath("native", "axven_native", "pyproject.toml").unlink()
        _must_reject_source(
            wheel_a, wheel_b, provenance_path, envelope_path,
            signed_source_root, git_root, missing, "missing authenticated build config",
        )
        checks += 1

        extra = _copy_source(rebuild_source_root, root / "extra")
        (extra / "unsigned-extra.txt").write_text("not part of closure\n", encoding="utf-8")
        _must_reject_source(
            wheel_a, wheel_b, provenance_path, envelope_path,
            signed_source_root, git_root, extra, "extra rebuild source file",
        )
        checks += 1

        symlinked = _copy_source(rebuild_source_root, root / "symlinked")
        link = symlinked.joinpath("native", "axven_native", "pyproject.toml")
        link.unlink()
        link.symlink_to(
            rebuild_source_root.joinpath("native", "axven_native", "pyproject.toml").resolve()
        )
        _must_reject_source(
            wheel_a, wheel_b, provenance_path, envelope_path,
            signed_source_root, git_root, symlinked, "rebuild source symlink substitution",
        )
        checks += 1

        mutated_wheel_dir = root / "mutated-wheel"
        mutated_wheel_dir.mkdir()
        mutated_wheel = mutated_wheel_dir / EXPECTED_WHEEL
        mutated_wheel.write_bytes(rebuilt_wheel.read_bytes() + b"\x00")
        _must_reject_full(
            wheel_a, wheel_b, provenance_path, envelope_path,
            signed_source_root, git_root, rebuild_source_root, mutated_wheel,
            "detached rebuilt wheel byte mutation",
        )
        checks += 1

        renamed = root / "renamed-rebuild.whl"
        renamed.write_bytes(rebuilt_wheel.read_bytes())
        _must_reject_full(
            wheel_a, wheel_b, provenance_path, envelope_path,
            signed_source_root, git_root, rebuild_source_root, renamed,
            "detached rebuilt wheel filename/path confusion",
        )
        checks += 1

    if checks != 8:
        raise AssertionError(checks)
    if _sha256_file(rebuilt_wheel) != wheel_sha_before:
        raise AssertionError("RUST-018 selftest mutated original rebuilt wheel")
    if _snapshot(rebuild_source_root) != source_before:
        raise AssertionError("RUST-018 selftest mutated original rebuild source")
    verify(
        wheel_a,
        wheel_b,
        provenance_path,
        envelope_path,
        signed_source_root,
        git_root,
        rebuild_source_root,
        rebuilt_wheel,
    )
    print("RUST-018 detached source rebuild fail-closed contract: 8/8 GREEN")


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("RUST-018 command required")
    command = sys.argv[1]
    if command == "sourcecheck":
        if len(sys.argv) != 9:
            raise SystemExit(
                "usage: rust_018_detached_rebuild_verify.py sourcecheck "
                "WHEEL_A WHEEL_B PROVENANCE ENVELOPE SIGNED_SOURCE_ROOT GIT_ROOT REBUILD_SOURCE_ROOT"
            )
        sourcecheck_only(*(Path(value) for value in sys.argv[2:9]))
        return
    if command in {"verify", "selftest"}:
        if len(sys.argv) != 10:
            raise SystemExit(
                "usage: rust_018_detached_rebuild_verify.py {verify|selftest} "
                "WHEEL_A WHEEL_B PROVENANCE ENVELOPE SIGNED_SOURCE_ROOT GIT_ROOT REBUILD_SOURCE_ROOT REBUILT_WHEEL"
            )
        args = tuple(Path(value) for value in sys.argv[2:10])
        if command == "verify":
            verify(*args)
        else:
            selftest(*args)
        return
    raise SystemExit(f"unknown RUST-018 command: {command}")


if __name__ == "__main__":
    main()
