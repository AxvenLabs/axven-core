#!/usr/bin/env python3
"""RUST-016: detached verification of signed build-input file contents."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import sys
import tempfile
import zipfile

# RUST-017 composes this verifier into another exact detached evidence tree.
# Prevent imported helper bytecode from mutating that tree between verification stages.
sys.dont_write_bytecode = True

import rust_015_offline_repro_consumer_verify as upstream

BUILD_INPUT_KEYS = frozenset(
    {
        "native/axven_native/Cargo.toml",
        "native/axven_native/Cargo.lock",
        "native/axven_native/src/lib.rs",
        "requirements-native-build.lock",
        "requirements-ci-runtime-posix.lock",
        "rust_009_portable_linux_wheel_spec.py",
        "rust_013_reproducible_wheel_spec.py",
        "rust_013_reproducible_build_policy_spec.py",
        "rust_014_reproducible_attestation.py",
        "rust_014_reproducible_attestation_policy_spec.py",
        ".github/workflows/native-reproducible-build.yml",
    }
)
HEX = frozenset("0123456789abcdef")


def _lower_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(ch in HEX for ch in value)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _allowed_directories() -> frozenset[str]:
    result: set[str] = set()
    for name in BUILD_INPUT_KEYS:
        parent = PurePosixPath(name).parent
        while parent.parts:
            result.add(parent.as_posix())
            parent = parent.parent
    return frozenset(result)


ALLOWED_DIRECTORIES = _allowed_directories()


def _assert_source_root(source_root: Path) -> None:
    if source_root.is_symlink():
        raise AssertionError("source-input root must not be a symlink")
    if not source_root.is_dir():
        raise AssertionError("source-input root must be a real directory")


def _validate_claims(build_inputs: object) -> dict[str, str]:
    if not isinstance(build_inputs, dict) or frozenset(build_inputs) != BUILD_INPUT_KEYS:
        raise AssertionError("unexpected signed build-input claim set")
    result: dict[str, str] = {}
    for name, digest in build_inputs.items():
        if name not in BUILD_INPUT_KEYS or not _lower_hex(digest, 64):
            raise AssertionError(f"invalid signed build-input claim: {name!r}")
        result[name] = digest
    return result


def _validate_source_tree(source_root: Path, build_inputs: object) -> dict[str, str]:
    _assert_source_root(source_root)
    claims = _validate_claims(build_inputs)
    seen_files: set[str] = set()
    seen_directories: set[str] = set()

    for entry in source_root.rglob("*"):
        relative = entry.relative_to(source_root).as_posix()
        if entry.is_symlink():
            raise AssertionError(f"source-input tree contains symlink: {relative}")
        if entry.is_dir():
            if relative not in ALLOWED_DIRECTORIES:
                raise AssertionError(f"unexpected source-input directory: {relative}")
            seen_directories.add(relative)
            continue
        if not entry.is_file():
            raise AssertionError(f"unsupported source-input filesystem object: {relative}")
        if relative not in BUILD_INPUT_KEYS:
            raise AssertionError(f"unexpected unsigned source-input file: {relative}")
        seen_files.add(relative)

    if seen_files != set(BUILD_INPUT_KEYS):
        missing = sorted(set(BUILD_INPUT_KEYS) - seen_files)
        extra = sorted(seen_files - set(BUILD_INPUT_KEYS))
        raise AssertionError(f"source-input path set mismatch: missing={missing!r} extra={extra!r}")

    required_directories = {
        PurePosixPath(name).parent.as_posix()
        for name in BUILD_INPUT_KEYS
        if PurePosixPath(name).parent.parts
    }
    for directory in tuple(required_directories):
        parent = PurePosixPath(directory).parent
        while parent.parts:
            required_directories.add(parent.as_posix())
            parent = parent.parent
    if seen_directories != required_directories:
        raise AssertionError("source-input directory set mismatch")

    actual: dict[str, str] = {}
    for name in sorted(BUILD_INPUT_KEYS):
        path = source_root.joinpath(*PurePosixPath(name).parts)
        if path.is_symlink() or not path.is_file():
            raise AssertionError(f"signed source-input must be a regular non-symlink file: {name}")
        digest = _sha256_file(path)
        if digest != claims[name]:
            raise AssertionError(f"signed build-input digest mismatch: {name}")
        actual[name] = digest
    return actual


def _verify(
    wheel_a: Path,
    wheel_b: Path,
    provenance_path: Path,
    envelope_path: Path,
    source_root: Path,
) -> tuple[str, str]:
    artifact_sha, source_commit = upstream._verify(
        wheel_a, wheel_b, provenance_path, envelope_path
    )
    _, provenance = upstream._load_canonical_json(
        provenance_path, label="reproducibility provenance"
    )
    _validate_source_tree(source_root, provenance["build_inputs"])
    return artifact_sha, source_commit


def verify(
    wheel_a: Path,
    wheel_b: Path,
    provenance_path: Path,
    envelope_path: Path,
    source_root: Path,
) -> None:
    artifact_sha, source_commit = _verify(
        wheel_a, wheel_b, provenance_path, envelope_path, source_root
    )
    print(
        "RUST-016 detached signed build-input verification: GREEN "
        f"artifact_sha256={artifact_sha} source={source_commit} inputs={len(BUILD_INPUT_KEYS)}"
    )


def _must_reject(
    wheel_a: Path,
    wheel_b: Path,
    provenance_path: Path,
    envelope_path: Path,
    source_root: Path,
    label: str,
) -> None:
    try:
        _verify(wheel_a, wheel_b, provenance_path, envelope_path, source_root)
    except (AssertionError, json.JSONDecodeError, UnicodeDecodeError, zipfile.BadZipFile):
        print(f"[GREEN] rejected {label}")
        return
    raise AssertionError(f"RUST-016 mutation unexpectedly accepted: {label}")


def _copy_source_tree(source_root: Path, destination: Path) -> Path:
    shutil.copytree(source_root, destination)
    return destination


def _source_snapshot(source_root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in sorted(BUILD_INPUT_KEYS):
        path = source_root.joinpath(*PurePosixPath(name).parts)
        if path.is_symlink() or not path.is_file():
            raise AssertionError(f"cannot snapshot source input: {name}")
        result[name] = _sha256_file(path)
    return result


def selftest(
    wheel_a: Path,
    wheel_b: Path,
    provenance_path: Path,
    envelope_path: Path,
    source_root: Path,
) -> None:
    verify(wheel_a, wheel_b, provenance_path, envelope_path, source_root)
    wheel_a_before = _sha256_file(wheel_a)
    wheel_b_before = _sha256_file(wheel_b)
    provenance_before = provenance_path.read_bytes()
    envelope_before = envelope_path.read_bytes()
    source_before = _source_snapshot(source_root)
    _, provenance = upstream._load_canonical_json(
        provenance_path, label="reproducibility provenance"
    )
    target_name = sorted(BUILD_INPUT_KEYS)[0]
    target_parts = PurePosixPath(target_name).parts
    checks = 0

    with tempfile.TemporaryDirectory(prefix="axven-rust016-") as temp:
        root = Path(temp)

        mutated_tree = _copy_source_tree(source_root, root / "byte-mutation")
        target = mutated_tree.joinpath(*target_parts)
        target.write_bytes(target.read_bytes() + b"\x00")
        _must_reject(
            wheel_a, wheel_b, provenance_path, envelope_path, mutated_tree,
            "source-input file byte mutation",
        )
        checks += 1

        missing_tree = _copy_source_tree(source_root, root / "missing-input")
        missing_tree.joinpath(*target_parts).unlink()
        _must_reject(
            wheel_a, wheel_b, provenance_path, envelope_path, missing_tree,
            "missing signed input",
        )
        checks += 1

        extra_tree = _copy_source_tree(source_root, root / "extra-input")
        (extra_tree / "unsigned-extra.txt").write_text("not signed\n", encoding="utf-8")
        _must_reject(
            wheel_a, wheel_b, provenance_path, envelope_path, extra_tree,
            "extra unsigned input",
        )
        checks += 1

        root_link = root / "source-root-link"
        root_link.symlink_to(source_root.resolve(), target_is_directory=True)
        _must_reject(
            wheel_a, wheel_b, provenance_path, envelope_path, root_link,
            "source-root symlink substitution",
        )
        checks += 1

        symlink_tree = _copy_source_tree(source_root, root / "input-symlink")
        symlink_target = symlink_tree.joinpath(*target_parts)
        symlink_target.unlink()
        symlink_target.symlink_to(source_root.joinpath(*target_parts).resolve())
        _must_reject(
            wheel_a, wheel_b, provenance_path, envelope_path, symlink_tree,
            "individual input symlink substitution",
        )
        checks += 1

        relocated_tree = _copy_source_tree(source_root, root / "relocated-input")
        relocated = relocated_tree.joinpath(*target_parts)
        relocated.rename(relocated.with_name(relocated.name + ".relocated"))
        _must_reject(
            wheel_a, wheel_b, provenance_path, envelope_path, relocated_tree,
            "signed-path relocation/confusion",
        )
        checks += 1

        mutated_provenance = copy.deepcopy(provenance)
        digest = mutated_provenance["build_inputs"][target_name]
        mutated_provenance["build_inputs"][target_name] = (
            ("0" if digest[0] != "0" else "1") + digest[1:]
        )
        mutated_provenance_path = root / "build-input-claim.json"
        mutated_provenance_path.write_bytes(upstream._canonical(mutated_provenance))
        _must_reject(
            wheel_a, wheel_b, mutated_provenance_path, envelope_path, source_root,
            "authenticated build-input claim mutation",
        )
        checks += 1

        mutated_wheel_dir = root / "mutated-wheel"
        mutated_wheel_dir.mkdir()
        mutated_wheel = mutated_wheel_dir / upstream.WHEEL_FILENAME
        mutated_wheel.write_bytes(wheel_b.read_bytes() + b"\x00")
        _must_reject(
            wheel_a, mutated_wheel, provenance_path, envelope_path, source_root,
            "upstream wheel byte mutation",
        )
        checks += 1

    if checks != 8:
        raise AssertionError(checks)
    if _sha256_file(wheel_a) != wheel_a_before or _sha256_file(wheel_b) != wheel_b_before:
        raise AssertionError("RUST-016 selftest mutated original wheels")
    if provenance_path.read_bytes() != provenance_before:
        raise AssertionError("RUST-016 selftest mutated original provenance")
    if envelope_path.read_bytes() != envelope_before:
        raise AssertionError("RUST-016 selftest mutated original envelope")
    if _source_snapshot(source_root) != source_before:
        raise AssertionError("RUST-016 selftest mutated original source-input tree")
    verify(wheel_a, wheel_b, provenance_path, envelope_path, source_root)
    print("RUST-016 detached signed build-input fail-closed contract: 8/8 GREEN")


def main() -> None:
    if len(sys.argv) != 7 or sys.argv[1] not in {"verify", "selftest"}:
        raise SystemExit(
            "usage: rust_016_offline_build_input_verify.py {verify|selftest} "
            "WHEEL_A WHEEL_B PROVENANCE ENVELOPE SOURCE_INPUT_ROOT"
        )
    command = sys.argv[1]
    wheel_a = Path(sys.argv[2])
    wheel_b = Path(sys.argv[3])
    provenance_path = Path(sys.argv[4])
    envelope_path = Path(sys.argv[5])
    source_root = Path(sys.argv[6])
    if command == "verify":
        verify(wheel_a, wheel_b, provenance_path, envelope_path, source_root)
    else:
        selftest(wheel_a, wheel_b, provenance_path, envelope_path, source_root)


if __name__ == "__main__":
    main()
