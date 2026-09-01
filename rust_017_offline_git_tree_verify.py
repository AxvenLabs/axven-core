#!/usr/bin/env python3
"""RUST-017: detached Git commit/tree membership proof for signed build inputs."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import sys
import tempfile
import zipfile

import rust_015_offline_repro_consumer_verify as evidence
import rust_016_offline_build_input_verify as sourcecheck

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
EXPECTED_TREE_COUNT = 6
HEX = frozenset("0123456789abcdef")
REGULAR_FILE_MODES = frozenset({"100644", "100755"})
TREE_MODE = "40000"


def _lower_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(ch in HEX for ch in value)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_oid(kind: str, payload: bytes) -> str:
    if kind not in {"commit", "tree", "blob"}:
        raise AssertionError(f"unsupported Git object kind: {kind}")
    header = f"{kind} {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


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


def _parse_commit(payload: bytes) -> tuple[str, int]:
    header_block, separator, _message = payload.partition(b"\n\n")
    if not separator:
        raise AssertionError("Git commit object has no header/message separator")
    lines = header_block.splitlines()
    tree_lines = [line for line in lines if line.startswith(b"tree ")]
    committer_lines = [line for line in lines if line.startswith(b"committer ")]
    if len(tree_lines) != 1:
        raise AssertionError("Git commit must contain exactly one root tree header")
    if len(committer_lines) != 1:
        raise AssertionError("Git commit must contain exactly one committer header")

    tree_raw = tree_lines[0][5:]
    try:
        tree_oid = tree_raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AssertionError("Git commit root tree id is not ASCII") from exc
    if not _lower_hex(tree_oid, 40):
        raise AssertionError("invalid Git commit root tree id")

    try:
        _identity, epoch_raw, timezone_raw = committer_lines[0].rsplit(b" ", 2)
    except ValueError as exc:
        raise AssertionError("malformed Git committer header") from exc
    if not epoch_raw.isdigit():
        raise AssertionError("Git committer timestamp is not decimal")
    if (
        len(timezone_raw) != 5
        or timezone_raw[:1] not in {b"+", b"-"}
        or not timezone_raw[1:].isdigit()
    ):
        raise AssertionError("malformed Git committer timezone")
    epoch = int(epoch_raw)
    if epoch < 315532800:
        raise AssertionError("Git committer timestamp is implausibly old")
    return tree_oid, epoch


def _parse_tree(payload: bytes) -> dict[bytes, tuple[str, str]]:
    entries: dict[bytes, tuple[str, str]] = {}
    cursor = 0
    while cursor < len(payload):
        space = payload.find(b" ", cursor)
        if space <= cursor:
            raise AssertionError("malformed Git tree mode field")
        nul = payload.find(b"\x00", space + 1)
        if nul <= space + 1:
            raise AssertionError("malformed Git tree name field")
        if nul + 21 > len(payload):
            raise AssertionError("truncated Git tree object id")

        mode_raw = payload[cursor:space]
        name = payload[space + 1 : nul]
        oid_raw = payload[nul + 1 : nul + 21]
        cursor = nul + 21

        if not mode_raw.isdigit():
            raise AssertionError("non-decimal Git tree mode")
        try:
            mode = mode_raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise AssertionError("non-ASCII Git tree mode") from exc
        if not name or b"/" in name or name in {b".", b".."}:
            raise AssertionError("unsafe Git tree entry name")
        if name in entries:
            raise AssertionError("duplicate Git tree entry name")
        if len(oid_raw) != 20:
            raise AssertionError("invalid Git tree object id length")
        entries[name] = (mode, oid_raw.hex())

    if cursor != len(payload):
        raise AssertionError("trailing bytes in Git tree object")
    return entries


def _load_git_objects(git_root: Path) -> tuple[bytes, dict[str, dict[bytes, tuple[str, str]]]]:
    _assert_real_directory(git_root, "Git object root")
    root_entries = {entry.name for entry in git_root.iterdir()}
    if root_entries != {"commit.object", "trees"}:
        raise AssertionError(f"unexpected Git object root layout: {sorted(root_entries)!r}")

    commit_path = git_root / "commit.object"
    trees_root = git_root / "trees"
    _assert_regular_file(commit_path, "Git commit object")
    _assert_real_directory(trees_root, "Git tree-object directory")

    tree_files = sorted(trees_root.iterdir(), key=lambda path: path.name)
    if len(tree_files) != EXPECTED_TREE_COUNT:
        raise AssertionError(
            f"expected exactly {EXPECTED_TREE_COUNT} detached Git tree objects, got {len(tree_files)}"
        )

    trees: dict[str, dict[bytes, tuple[str, str]]] = {}
    for path in tree_files:
        _assert_regular_file(path, f"Git tree object {path.name}")
        if path.suffix != ".tree":
            raise AssertionError(f"unexpected Git tree object filename: {path.name}")
        oid = path.stem
        if not _lower_hex(oid, 40):
            raise AssertionError(f"invalid Git tree object filename id: {path.name}")
        raw = path.read_bytes()
        if _git_oid("tree", raw) != oid:
            raise AssertionError(f"Git tree payload/object-id mismatch: {path.name}")
        if oid in trees:
            raise AssertionError(f"duplicate detached Git tree object: {oid}")
        trees[oid] = _parse_tree(raw)

    return commit_path.read_bytes(), trees


def _prove_paths(
    root_tree_oid: str,
    trees: dict[str, dict[bytes, tuple[str, str]]],
    source_root: Path,
) -> None:
    visited_tree_oids: set[str] = set()

    for relative in sorted(BUILD_INPUT_KEYS):
        components = PurePosixPath(relative).parts
        current_tree = root_tree_oid
        for index, component in enumerate(components):
            entries = trees.get(current_tree)
            if entries is None:
                raise AssertionError(
                    f"missing detached Git tree object while walking {relative}: {current_tree}"
                )
            visited_tree_oids.add(current_tree)
            key = component.encode("utf-8")
            if key not in entries:
                raise AssertionError(f"Git commit tree does not contain signed path: {relative}")
            mode, child_oid = entries[key]
            terminal = index == len(components) - 1
            if not terminal:
                if mode != TREE_MODE:
                    raise AssertionError(
                        f"non-tree intermediate Git path component for {relative}: {component} mode={mode}"
                    )
                current_tree = child_oid
                continue

            if mode not in REGULAR_FILE_MODES:
                raise AssertionError(
                    f"signed Git path is not a regular file blob: {relative} mode={mode}"
                )
            source_path = source_root.joinpath(*components)
            _assert_regular_file(source_path, f"signed source input {relative}")
            actual_blob = _git_oid("blob", source_path.read_bytes())
            if actual_blob != child_oid:
                raise AssertionError(f"Git blob membership mismatch: {relative}")

    if visited_tree_oids != set(trees):
        unused = sorted(set(trees) - visited_tree_oids)
        missing = sorted(visited_tree_oids - set(trees))
        raise AssertionError(f"detached Git tree closure mismatch: unused={unused!r} missing={missing!r}")


def _verify(
    wheel_a: Path,
    wheel_b: Path,
    provenance_path: Path,
    envelope_path: Path,
    source_root: Path,
    git_root: Path,
) -> tuple[str, str]:
    artifact_sha, source_commit = sourcecheck._verify(
        wheel_a, wheel_b, provenance_path, envelope_path, source_root
    )
    _, provenance = evidence._load_canonical_json(
        provenance_path, label="reproducibility provenance"
    )
    if frozenset(provenance["build_inputs"]) != BUILD_INPUT_KEYS:
        raise AssertionError("RUST-017 build-input key set drift")
    if provenance["source"]["commit"] != source_commit:
        raise AssertionError("RUST-017 source commit disagrees with upstream verification")

    commit_payload, trees = _load_git_objects(git_root)
    actual_commit = _git_oid("commit", commit_payload)
    if actual_commit != source_commit:
        raise AssertionError("detached Git commit object does not match signed source.commit")
    root_tree_oid, committer_epoch = _parse_commit(commit_payload)
    if committer_epoch != provenance["source_date_epoch"]:
        raise AssertionError("Git committer timestamp does not match signed source_date_epoch")
    if root_tree_oid not in trees:
        raise AssertionError("detached Git object bundle does not contain the commit root tree")
    _prove_paths(root_tree_oid, trees, source_root)
    return artifact_sha, source_commit


def verify(
    wheel_a: Path,
    wheel_b: Path,
    provenance_path: Path,
    envelope_path: Path,
    source_root: Path,
    git_root: Path,
) -> None:
    artifact_sha, source_commit = _verify(
        wheel_a, wheel_b, provenance_path, envelope_path, source_root, git_root
    )
    print(
        "RUST-017 detached Git commit/tree proof: GREEN "
        f"artifact_sha256={artifact_sha} source={source_commit} "
        f"inputs={len(BUILD_INPUT_KEYS)} trees={EXPECTED_TREE_COUNT}"
    )


def _must_reject(
    wheel_a: Path,
    wheel_b: Path,
    provenance_path: Path,
    envelope_path: Path,
    source_root: Path,
    git_root: Path,
    label: str,
) -> None:
    try:
        _verify(
            wheel_a, wheel_b, provenance_path, envelope_path, source_root, git_root
        )
    except (
        AssertionError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        OSError,
        zipfile.BadZipFile,
    ):
        print(f"[GREEN] rejected {label}")
        return
    raise AssertionError(f"RUST-017 mutation unexpectedly accepted: {label}")


def _copy_tree(source: Path, destination: Path) -> Path:
    shutil.copytree(source, destination)
    return destination


def _git_snapshot(git_root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for entry in sorted(git_root.rglob("*"), key=lambda path: path.as_posix()):
        if entry.is_symlink():
            raise AssertionError("cannot snapshot symlinked Git object bundle")
        if entry.is_file():
            result[entry.relative_to(git_root).as_posix()] = _sha256_file(entry)
    return result


def selftest(
    wheel_a: Path,
    wheel_b: Path,
    provenance_path: Path,
    envelope_path: Path,
    source_root: Path,
    git_root: Path,
) -> None:
    verify(wheel_a, wheel_b, provenance_path, envelope_path, source_root, git_root)
    wheel_a_before = _sha256_file(wheel_a)
    wheel_b_before = _sha256_file(wheel_b)
    provenance_before = provenance_path.read_bytes()
    envelope_before = envelope_path.read_bytes()
    source_before = sourcecheck._source_snapshot(source_root)
    git_before = _git_snapshot(git_root)
    _, provenance = evidence._load_canonical_json(
        provenance_path, label="reproducibility provenance"
    )
    target_source = sorted(BUILD_INPUT_KEYS)[0]
    target_parts = PurePosixPath(target_source).parts
    original_tree_files = sorted((git_root / "trees").iterdir(), key=lambda path: path.name)
    if len(original_tree_files) != EXPECTED_TREE_COUNT:
        raise AssertionError("unexpected original detached Git tree count")
    target_tree_name = original_tree_files[0].name
    checks = 0

    with tempfile.TemporaryDirectory(prefix="axven-rust017-") as temp:
        root = Path(temp)

        commit_mutation = _copy_tree(git_root, root / "commit-mutation")
        commit_path = commit_mutation / "commit.object"
        commit_path.write_bytes(commit_path.read_bytes() + b"\x00")
        _must_reject(
            wheel_a, wheel_b, provenance_path, envelope_path, source_root,
            commit_mutation, "raw commit-object byte mutation",
        )
        checks += 1

        commit_symlink = _copy_tree(git_root, root / "commit-symlink")
        commit_path = commit_symlink / "commit.object"
        commit_path.unlink()
        commit_path.symlink_to((git_root / "commit.object").resolve())
        _must_reject(
            wheel_a, wheel_b, provenance_path, envelope_path, source_root,
            commit_symlink, "commit-object symlink substitution",
        )
        checks += 1

        tree_mutation = _copy_tree(git_root, root / "tree-mutation")
        tree_path = tree_mutation / "trees" / target_tree_name
        tree_path.write_bytes(tree_path.read_bytes() + b"\x00")
        _must_reject(
            wheel_a, wheel_b, provenance_path, envelope_path, source_root,
            tree_mutation, "raw tree-object byte mutation",
        )
        checks += 1

        missing_tree = _copy_tree(git_root, root / "missing-tree")
        (missing_tree / "trees" / target_tree_name).unlink()
        _must_reject(
            wheel_a, wheel_b, provenance_path, envelope_path, source_root,
            missing_tree, "missing required tree object",
        )
        checks += 1

        extra_tree = _copy_tree(git_root, root / "extra-tree")
        empty_tree_payload = b""
        empty_tree_oid = _git_oid("tree", empty_tree_payload)
        extra_path = extra_tree / "trees" / f"{empty_tree_oid}.tree"
        if extra_path.exists():
            alternate_payload = b"100644 x\x00" + (b"\x00" * 20)
            empty_tree_oid = _git_oid("tree", alternate_payload)
            extra_path = extra_tree / "trees" / f"{empty_tree_oid}.tree"
            empty_tree_payload = alternate_payload
        extra_path.write_bytes(empty_tree_payload)
        _must_reject(
            wheel_a, wheel_b, provenance_path, envelope_path, source_root,
            extra_tree, "extra otherwise-valid tree object",
        )
        checks += 1

        tree_symlink = _copy_tree(git_root, root / "tree-symlink")
        tree_path = tree_symlink / "trees" / target_tree_name
        tree_path.unlink()
        tree_path.symlink_to((git_root / "trees" / target_tree_name).resolve())
        _must_reject(
            wheel_a, wheel_b, provenance_path, envelope_path, source_root,
            tree_symlink, "tree-object symlink substitution",
        )
        checks += 1

        source_mutation = _copy_tree(source_root, root / "source-mutation")
        source_path = source_mutation.joinpath(*target_parts)
        source_path.write_bytes(source_path.read_bytes() + b"\x00")
        _must_reject(
            wheel_a, wheel_b, provenance_path, envelope_path, source_mutation,
            git_root, "signed source-input byte mutation",
        )
        checks += 1

        source_relocation = _copy_tree(source_root, root / "source-relocation")
        source_path = source_relocation.joinpath(*target_parts)
        source_path.rename(source_path.with_name(source_path.name + ".relocated"))
        _must_reject(
            wheel_a, wheel_b, provenance_path, envelope_path, source_relocation,
            git_root, "signed source-input path relocation",
        )
        checks += 1

        commit_claim = copy.deepcopy(provenance)
        signed_commit = commit_claim["source"]["commit"]
        commit_claim["source"]["commit"] = (
            ("0" if signed_commit[0] != "0" else "1") + signed_commit[1:]
        )
        commit_claim_path = root / "source-commit-claim.json"
        commit_claim_path.write_bytes(evidence._canonical(commit_claim))
        _must_reject(
            wheel_a, wheel_b, commit_claim_path, envelope_path, source_root,
            git_root, "signed source.commit claim mutation",
        )
        checks += 1

        epoch_claim = copy.deepcopy(provenance)
        epoch_claim["source_date_epoch"] += 2
        epoch_claim_path = root / "source-epoch-claim.json"
        epoch_claim_path.write_bytes(evidence._canonical(epoch_claim))
        _must_reject(
            wheel_a, wheel_b, epoch_claim_path, envelope_path, source_root,
            git_root, "signed source_date_epoch claim mutation",
        )
        checks += 1

    if checks != 10:
        raise AssertionError(checks)
    if _sha256_file(wheel_a) != wheel_a_before or _sha256_file(wheel_b) != wheel_b_before:
        raise AssertionError("RUST-017 selftest mutated original wheels")
    if provenance_path.read_bytes() != provenance_before:
        raise AssertionError("RUST-017 selftest mutated original provenance")
    if envelope_path.read_bytes() != envelope_before:
        raise AssertionError("RUST-017 selftest mutated original envelope")
    if sourcecheck._source_snapshot(source_root) != source_before:
        raise AssertionError("RUST-017 selftest mutated original source-input tree")
    if _git_snapshot(git_root) != git_before:
        raise AssertionError("RUST-017 selftest mutated original Git-object bundle")
    verify(wheel_a, wheel_b, provenance_path, envelope_path, source_root, git_root)
    print("RUST-017 detached Git commit/tree fail-closed contract: 10/10 GREEN")


def main() -> None:
    if len(sys.argv) != 8 or sys.argv[1] not in {"verify", "selftest"}:
        raise SystemExit(
            "usage: rust_017_offline_git_tree_verify.py {verify|selftest} "
            "WHEEL_A WHEEL_B PROVENANCE ENVELOPE SOURCE_INPUT_ROOT GIT_OBJECT_ROOT"
        )
    command = sys.argv[1]
    wheel_a = Path(sys.argv[2])
    wheel_b = Path(sys.argv[3])
    provenance_path = Path(sys.argv[4])
    envelope_path = Path(sys.argv[5])
    source_root = Path(sys.argv[6])
    git_root = Path(sys.argv[7])
    if command == "verify":
        verify(
            wheel_a, wheel_b, provenance_path, envelope_path, source_root, git_root
        )
    else:
        selftest(
            wheel_a, wheel_b, provenance_path, envelope_path, source_root, git_root
        )


if __name__ == "__main__":
    main()
