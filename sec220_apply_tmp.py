from pathlib import Path
import hashlib, json

path = Path("runtime_provenance.py")
source = path.read_text(encoding="utf-8")

if "import importlib.metadata as importlib_metadata" not in source:
    source = source.replace(
        "import hashlib\n",
        "import hashlib\nimport importlib.metadata as importlib_metadata\n",
        1,
    )

if "RUNTIME_DISTRIBUTIONS =" not in source:
    constants = (
        "HASH_CHUNK_BYTES = 64 * 1024\n\n"
        "# SEC-220: the validated-runtime receipt must bind the actual installed\n"
        "# runtime dependency contents, not only their lock files/version labels.\n"
        "RUNTIME_DISTRIBUTIONS = {\n"
        '    "cryptography": ("50.0.1", True),\n'
        '    "cffi": ("2.1.1", True),\n'
        '    "pycparser": ("3.0", True),\n'
        '    "dilithium-py": ("1.4.0", False),\n'
        "}\n"
        "MAX_RUNTIME_DIST_FILES = 8192\n"
        "MAX_RUNTIME_DIST_FILE_BYTES = 128 * 1024 * 1024\n"
        "MAX_RUNTIME_DIST_TOTAL_BYTES = 512 * 1024 * 1024\n"
    )
    source = source.replace("HASH_CHUNK_BYTES = 64 * 1024\n", constants, 1)

implementation = r'''
def _hash_runtime_distribution_file(path: Path, *, label: str) -> tuple[int, str]:
    """Hash one installed dependency file through a descriptor-bound read."""
    try:
        before = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"runtime distribution file is missing: {label}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"runtime distribution file is not regular: {label}")
    if before.st_size < 0 or before.st_size > MAX_RUNTIME_DIST_FILE_BYTES:
        raise RuntimeError(f"runtime distribution file exceeds size budget: {label}")

    digest = hashlib.sha256()
    remaining = before.st_size
    try:
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or not _same_file(before, opened)
                or opened.st_size != before.st_size
            ):
                raise RuntimeError(f"runtime distribution file changed before hashing: {label}")
            while remaining:
                chunk = handle.read(min(HASH_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
            extra = handle.read(1)
    except RuntimeError:
        raise
    except OSError as exc:
        raise RuntimeError(f"runtime distribution file is unreadable: {label}") from exc

    if remaining or extra:
        raise RuntimeError(f"runtime distribution file changed while hashing: {label}")
    try:
        after = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"runtime distribution file changed after hashing: {label}") from exc
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or not _same_file(opened, after)
        or after.st_size != opened.st_size
    ):
        raise RuntimeError(f"runtime distribution file changed after hashing: {label}")
    return opened.st_size, digest.hexdigest()


def _runtime_distribution_snapshot() -> dict[str, dict[str, object]]:
    """Return compact content fingerprints for every pinned runtime distribution."""
    snapshot: dict[str, dict[str, object]] = {}
    total_files = 0
    total_bytes = 0

    for name, (expected_version, required) in RUNTIME_DISTRIBUTIONS.items():
        try:
            distribution = importlib_metadata.distribution(name)
        except importlib_metadata.PackageNotFoundError as exc:
            if required:
                raise RuntimeError(f"required runtime distribution is missing: {name}") from exc
            snapshot[name] = {"present": False}
            continue

        version = str(distribution.version)
        if version != expected_version:
            raise RuntimeError(
                f"runtime distribution version mismatch: {name} {version} != {expected_version}"
            )
        files = distribution.files
        if not files:
            raise RuntimeError(f"runtime distribution has no file inventory: {name}")

        rows: list[tuple[str, int, str]] = []
        seen: set[str] = set()
        dist_bytes = 0
        for item in files:
            raw = str(item).replace("\\", "/")
            pure = _canonical_manifest_name(raw)
            if pure is None or raw in seen:
                raise RuntimeError(f"invalid runtime distribution file entry: {name}:{raw}")
            seen.add(raw)
            total_files += 1
            if total_files > MAX_RUNTIME_DIST_FILES:
                raise RuntimeError("runtime distribution inventory exceeds file-count budget")

            file_path = Path(distribution.locate_file(item))
            size, digest = _hash_runtime_distribution_file(
                file_path, label=f"{name}:{raw}"
            )
            if total_bytes > MAX_RUNTIME_DIST_TOTAL_BYTES - size:
                raise RuntimeError("runtime distribution inventory exceeds aggregate byte budget")
            total_bytes += size
            dist_bytes += size
            rows.append((raw, size, digest))

        rows.sort(key=lambda row: row[0])
        aggregate = hashlib.sha256()
        for raw, size, digest in rows:
            aggregate.update(raw.encode("utf-8"))
            aggregate.update(b"\0")
            aggregate.update(str(size).encode("ascii"))
            aggregate.update(b"\0")
            aggregate.update(digest.encode("ascii"))
            aggregate.update(b"\n")

        snapshot[name] = {
            "present": True,
            "version": version,
            "files": len(rows),
            "bytes": dist_bytes,
            "sha256": aggregate.hexdigest(),
        }

    return snapshot
'''

anchor = "\ndef _trust_inputs_for_profile(profile: str) -> tuple[str, ...]:\n"
if "def _runtime_distribution_snapshot()" not in source:
    if anchor not in source:
        raise SystemExit("SEC-220 insertion anchor missing")
    source = source.replace(anchor, "\n" + implementation + anchor, 1)

old = (
    '    return {\n'
    '        "schema": RECEIPT_SCHEMA,\n'
    '        "python_version": python_version,\n'
    '        "inputs": inputs,\n'
    '    }\n'
)
new = (
    '    return {\n'
    '        "schema": RECEIPT_SCHEMA,\n'
    '        "python_version": python_version,\n'
    '        "inputs": inputs,\n'
    '        "runtime_distributions": _runtime_distribution_snapshot(),\n'
    '    }\n'
)
if '"runtime_distributions": _runtime_distribution_snapshot(),' not in source:
    if old not in source:
        raise SystemExit("SEC-220 receipt anchor missing")
    source = source.replace(old, new, 1)

path.write_text(source, encoding="utf-8", newline="\n")

manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in (
    "runtime_provenance.py",
    "security_sec220_runtime_dependency_content_provenance_spec.py",
):
    data = Path(name).read_bytes()
    manifest["files"][name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest["files"] = dict(sorted(manifest["files"].items()))
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
