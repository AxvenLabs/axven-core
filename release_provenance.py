#!/usr/bin/env python3
"""SEC-208: fail-closed provenance gate for public release tags."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
MANIFEST_NAME = "release_manifest.json"
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LEGACY_RELEASE_TAGS = frozenset({"v0.9.0-devnet"})
CANONICAL_ORIGIN_URLS = frozenset(
    {
        "https://github.com/AxvenLabs/axven-core",
        "https://github.com/AxvenLabs/axven-core.git",
        "git@github.com:AxvenLabs/axven-core.git",
        "ssh://git@github.com/AxvenLabs/axven-core.git",
    }
)


def _git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        ["git", "-C", str(Path(root).resolve()), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        check=False,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"git command failed: {' '.join(args)}")
    return proc


def _git_bytes(root: Path, *args: str) -> bytes:
    proc = subprocess.run(
        ["git", "-C", str(Path(root).resolve()), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git command failed: {' '.join(args)}")
    return proc.stdout


def _canonical_sha(value: object, regex: re.Pattern[str], label: str) -> str:
    if type(value) is not str or regex.fullmatch(value) is None:
        raise RuntimeError(f"{label} must be canonical lowercase hex")
    return value


def _canonical_tag(root: Path, tag: object) -> str:
    if type(tag) is not str or not tag or len(tag) > 128 or tag.strip() != tag:
        raise RuntimeError("release tag is not canonical")
    if tag in LEGACY_RELEASE_TAGS:
        raise RuntimeError("legacy release tag must never be reused or moved")
    probe = _git(root, "check-ref-format", f"refs/tags/{tag}", check=False)
    if probe.returncode != 0:
        raise RuntimeError("release tag is not a valid Git ref")
    return tag


def _assert_canonical_origin(root: Path) -> str:
    origin = _git(root, "remote", "get-url", "origin").stdout.strip()
    if origin not in CANONICAL_ORIGIN_URLS:
        raise RuntimeError("release repository origin is not canonical AxvenLabs/axven-core")
    return origin


def _assert_clean_tracked_tree(root: Path) -> None:
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=no").stdout
    if status.strip():
        raise RuntimeError("release checkout has tracked modifications")


def _head_commit(root: Path) -> str:
    sha = _git(root, "rev-parse", "--verify", "HEAD").stdout.strip()
    return _canonical_sha(sha, SHA40_RE, "release commit SHA")


def _worktree_manifest_digest(root: Path) -> str:
    path = Path(root).resolve() / MANIFEST_NAME
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("release manifest must be a regular non-symlink file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _local_tag_exists(root: Path, tag: str) -> bool:
    result = _git(root, "show-ref", "--verify", "--quiet", f"refs/tags/{tag}", check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError("unable to determine local release tag state")
    return result.returncode == 0


def _remote_tag_object(root: Path, tag: str) -> str | None:
    result = _git(
        root,
        "ls-remote",
        "--exit-code",
        "--refs",
        "origin",
        f"refs/tags/{tag}",
        check=False,
    )
    if result.returncode == 2:
        return None
    if result.returncode != 0:
        raise RuntimeError("unable to determine remote release tag state")
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError("remote release tag lookup is ambiguous")
    parts = lines[0].split("\t", 1)
    if len(parts) != 2 or parts[1] != f"refs/tags/{tag}":
        raise RuntimeError("remote release tag lookup is malformed")
    return _canonical_sha(parts[0], SHA40_RE, "remote tag object SHA")


def prepare(
    root: Path,
    tag: object,
    *,
    require_canonical_origin: bool = True,
    check_remote: bool = True,
) -> dict[str, str]:
    root = Path(root).resolve()
    tag_name = _canonical_tag(root, tag)
    if require_canonical_origin:
        _assert_canonical_origin(root)
    _assert_clean_tracked_tree(root)
    commit = _head_commit(root)
    manifest_digest = _worktree_manifest_digest(root)
    if _local_tag_exists(root, tag_name):
        raise RuntimeError("release tag already exists locally; never reuse or move a release tag")
    if check_remote and _remote_tag_object(root, tag_name) is not None:
        raise RuntimeError("release tag already exists remotely; never reuse or move a release tag")
    return {
        "tag": tag_name,
        "release_commit_sha": commit,
        "release_manifest_sha256": manifest_digest,
    }


def verify(
    root: Path,
    tag: object,
    expected_commit: object,
    expected_manifest_digest: object,
    *,
    require_canonical_origin: bool = True,
    check_remote: bool = True,
) -> dict[str, str]:
    root = Path(root).resolve()
    tag_name = _canonical_tag(root, tag)
    commit = _canonical_sha(expected_commit, SHA40_RE, "release commit SHA")
    manifest_digest = _canonical_sha(
        expected_manifest_digest,
        SHA256_RE,
        "release_manifest.json SHA-256",
    )
    if require_canonical_origin:
        _assert_canonical_origin(root)
    _assert_clean_tracked_tree(root)
    if _head_commit(root) != commit:
        raise RuntimeError("release checkout HEAD does not match published release commit SHA")
    if not _local_tag_exists(root, tag_name):
        raise RuntimeError("release tag does not exist locally")

    tag_object = _git(root, "rev-parse", "--verify", f"refs/tags/{tag_name}").stdout.strip()
    tag_object = _canonical_sha(tag_object, SHA40_RE, "local tag object SHA")
    tag_type = _git(root, "cat-file", "-t", f"refs/tags/{tag_name}").stdout.strip()
    if tag_type != "tag":
        raise RuntimeError("release tag must be annotated")

    tag_commit = _git(
        root,
        "rev-parse",
        "--verify",
        f"refs/tags/{tag_name}^{{commit}}",
    ).stdout.strip()
    tag_commit = _canonical_sha(tag_commit, SHA40_RE, "tag target commit SHA")
    if tag_commit != commit:
        raise RuntimeError("release tag target does not match published release commit SHA")

    tagged_manifest = _git_bytes(root, "show", f"refs/tags/{tag_name}:{MANIFEST_NAME}")
    tagged_digest = hashlib.sha256(tagged_manifest).hexdigest()
    if tagged_digest != manifest_digest:
        raise RuntimeError("tagged release manifest does not match published trust anchor")

    if check_remote:
        remote_object = _remote_tag_object(root, tag_name)
        if remote_object is None:
            raise RuntimeError("release tag is not published on origin")
        if remote_object != tag_object:
            raise RuntimeError("remote release tag object differs from locally verified tag")

    return {
        "tag": tag_name,
        "release_commit_sha": commit,
        "release_manifest_sha256": manifest_digest,
        "tag_object_sha": tag_object,
    }


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(args) == 2 and args[0] == "prepare":
            result = prepare(ROOT, args[1])
            print(f"Release tag: {result['tag']}")
            print(f"release commit SHA: {result['release_commit_sha']}")
            print(f"release_manifest.json SHA-256: {result['release_manifest_sha256']}")
            return 0
        if len(args) == 4 and args[0] == "verify":
            result = verify(ROOT, args[1], args[2], args[3])
            print("Release provenance: GREEN")
            print(f"Release tag: {result['tag']}")
            print(f"release commit SHA: {result['release_commit_sha']}")
            print(f"release_manifest.json SHA-256: {result['release_manifest_sha256']}")
            return 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"release provenance failed: {exc}", file=sys.stderr)
        return 2

    print("usage:", file=sys.stderr)
    print("  python release_provenance.py prepare <new-tag>", file=sys.stderr)
    print(
        "  python release_provenance.py verify <tag> <release-commit-sha> <release-manifest-sha256>",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
