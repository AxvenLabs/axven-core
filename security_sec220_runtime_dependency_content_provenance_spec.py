#!/usr/bin/env python3
"""SEC-220: validated runtime receipts must bind installed dependency contents."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path, PurePosixPath

import axven
import runtime_provenance

ROOT = Path(__file__).resolve().parent


class _FakeDistribution:
    def __init__(self, root: Path, name: str, version: str) -> None:
        self.root = root
        self.version = version
        package = name.replace("-", "_")
        self.files = [
            PurePosixPath(f"{package}/module.py"),
            PurePosixPath(f"{name}-{version}.dist-info/METADATA"),
        ]
        for index, item in enumerate(self.files):
            path = self.locate_file(item)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"{name}:{version}:{index}\n".encode("utf-8"))

    def locate_file(self, item) -> Path:
        pure = PurePosixPath(str(item))
        return self.root.joinpath(*pure.parts)


def _fake_trust_root(root: Path) -> None:
    for index, name in enumerate(runtime_provenance.TRUST_INPUTS):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"trusted-{index}\n".encode("utf-8"))


def main() -> None:
    checks = 0

    canonical = runtime_provenance._runtime_distribution_snapshot()
    for name in ("cryptography", "cffi", "pycparser"):
        entry = canonical[name]
        assert entry["present"] is True, name
        assert entry["version"] == runtime_provenance.RUNTIME_DISTRIBUTIONS[name][0], name
        assert entry["files"] > 0, name
        assert entry["bytes"] > 0, name
        assert len(entry["sha256"]) == 64, name
    optional = canonical["dilithium-py"]
    if optional["present"]:
        assert optional["version"] == "1.4.0"
        assert optional["files"] > 0
    checks += 1
    print("[GREEN] canonical validated runtime has content fingerprints for pinned dependencies")

    original_distribution = runtime_provenance.importlib_metadata.distribution
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        fake = {
            name: _FakeDistribution(root / name, name, version)
            for name, (version, _required) in runtime_provenance.RUNTIME_DISTRIBUTIONS.items()
        }
        runtime_provenance.importlib_metadata.distribution = lambda name: fake[name]
        try:
            first = runtime_provenance._runtime_distribution_snapshot()
            victim = fake["cryptography"].locate_file(fake["cryptography"].files[0])
            data = victim.read_bytes()
            victim.write_bytes(bytes([data[0] ^ 1]) + data[1:])
            second = runtime_provenance._runtime_distribution_snapshot()
        finally:
            runtime_provenance.importlib_metadata.distribution = original_distribution
        assert first["cryptography"]["sha256"] != second["cryptography"]["sha256"]
        for name in ("cffi", "pycparser", "dilithium-py"):
            assert first[name] == second[name], name
    checks += 1
    print("[GREEN] same-size installed dependency tampering changes the runtime fingerprint")

    original_distribution = runtime_provenance.importlib_metadata.distribution
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        fake = {
            name: _FakeDistribution(root / name, name, version)
            for name, (version, _required) in runtime_provenance.RUNTIME_DISTRIBUTIONS.items()
        }
        runtime_provenance.importlib_metadata.distribution = lambda name: fake[name]
        try:
            victim = fake["cffi"].locate_file(fake["cffi"].files[0])
            victim.unlink()
            try:
                runtime_provenance._runtime_distribution_snapshot()
            except RuntimeError:
                pass
            else:
                raise AssertionError("runtime dependency provenance accepted a missing installed file")
        finally:
            runtime_provenance.importlib_metadata.distribution = original_distribution
    checks += 1
    print("[GREEN] missing installed dependency payloads fail closed")

    original_distribution = runtime_provenance.importlib_metadata.distribution
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _fake_trust_root(root)
        fake = {
            name: _FakeDistribution(root / ("dist-" + name), name, version)
            for name, (version, _required) in runtime_provenance.RUNTIME_DISTRIBUTIONS.items()
        }
        runtime_provenance.importlib_metadata.distribution = lambda name: fake[name]
        try:
            before = runtime_provenance.build_receipt(
                root, python_version=runtime_provenance.REQUIRED_PYTHON
            )
            assert "runtime_distributions" in before
            victim = fake["pycparser"].locate_file(fake["pycparser"].files[0])
            data = victim.read_bytes()
            victim.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
            after = runtime_provenance.build_receipt(
                root, python_version=runtime_provenance.REQUIRED_PYTHON
            )
        finally:
            runtime_provenance.importlib_metadata.distribution = original_distribution
        assert before != after
        assert before["inputs"] == after["inputs"]
        assert before["runtime_distributions"] != after["runtime_distributions"]
    checks += 1
    print("[GREEN] runtime receipt changes when installed dependency content changes")

    source = (ROOT / "runtime_provenance.py").read_text(encoding="utf-8")
    assert "runtime_distributions" in source
    assert "_runtime_distribution_snapshot" in source
    assert "importlib.metadata" in source
    assert "MAX_RUNTIME_DIST_TOTAL_BYTES" in source
    checks += 1
    print("[GREEN] runtime provenance implementation carries bounded dependency-content binding")

    manifest = json.loads((ROOT / "release_manifest.json").read_text(encoding="utf-8"))
    for name in (
        "runtime_provenance.py",
        "security_sec220_runtime_dependency_content_provenance_spec.py",
    ):
        assert name in manifest["files"], name
    checks += 1
    print("[GREEN] release manifest covers SEC-220 implementation and regression")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks += 1
    print("[GREEN] SEC-220 leaves canonical chain identity unchanged")

    assert checks == 7, checks
    print("SEC-220 runtime dependency content provenance: 7/7 GREEN")


if __name__ == "__main__":
    main()
