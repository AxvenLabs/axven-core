#!/usr/bin/env python3
"""RUST-016: static policy for the repository-blind native source-closure build."""
from __future__ import annotations

from pathlib import Path

import axven
import rust_014_reproducible_attestation as att
import rust_016_source_closure_spec as closure_spec

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-reproducible-build.yml"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")
EXPECTED_SOURCE_KEYS = {"Cargo.toml", "Cargo.lock", "src/lib.rs"}


def text(path: Path | str) -> str:
    target = path if isinstance(path, Path) else ROOT / path
    return target.read_text(encoding="utf-8")


def main() -> None:
    checks = 0
    workflow = text(WORKFLOW)
    doc = text("RUST_016.md")

    assert set(closure_spec.CANONICAL) == EXPECTED_SOURCE_KEYS
    assert closure_spec.CANONICAL["Cargo.toml"] == ROOT / "native/axven_native/Cargo.toml"
    assert closure_spec.CANONICAL["Cargo.lock"] == ROOT / "native/axven_native/Cargo.lock"
    assert closure_spec.CANONICAL["src/lib.rs"] == ROOT / "native/axven_native/src/lib.rs"
    source_spec = text("rust_016_source_closure_spec.py")
    assert "RUST-016 exact native source closure contract: 4/4 GREEN" in source_spec
    assert "frozenset(files) != frozenset(CANONICAL)" in source_spec
    assert "staged.read_bytes() != canonical.read_bytes()" in source_spec
    checks += 1
    print("[GREEN] RUST-016 source closure is exactly Cargo.toml, Cargo.lock, and src/lib.rs with byte equality")

    for marker in (
        '"RUST_016.md"',
        '"rust_016_source_closure_spec.py"',
        '"rust_016_hermetic_source_closure_policy_spec.py"',
        "python rust_016_hermetic_source_closure_policy_spec.py",
        "Stage exact RUST-016 native source closure",
        "python rust_016_source_closure_spec.py \"$closure\"",
        "Build RUST-016 repository-blind source closure",
        "Prove RUST-016 closure wheel equals ordinary reproducible build",
    ):
        assert marker in workflow, marker
    assert workflow.count('install -m 0444 native/axven_native/Cargo.toml "$closure/Cargo.toml"') == 1
    assert workflow.count('install -m 0444 native/axven_native/Cargo.lock "$closure/Cargo.lock"') == 1
    assert workflow.count('install -m 0444 native/axven_native/src/lib.rs "$closure/src/lib.rs"') == 1
    checks += 1
    print("[GREEN] workflow stages only the exact three native source files and rechecks the closure contract")

    start = workflow.index("- name: Build RUST-016 repository-blind source closure")
    end = workflow.index("- name: Prove RUST-016 closure wheel equals ordinary reproducible build", start)
    build = workflow[start:end]
    assert '-v "$closure:/src:ro"' in build
    assert '-v "$GITHUB_WORKSPACE/requirements-native-build.lock:/requirements-native-build.lock:ro"' in build
    assert '-v "$GITHUB_WORKSPACE:/work"' not in build
    assert "-w /work" not in build
    assert "/work/native/axven_native" not in build
    assert "CARGO_TARGET_DIR=/target" in build
    assert "SOURCE_DATE_EPOCH=\"$SOURCE_DATE_EPOCH\"" in build
    assert "CARGO_INCREMENTAL=0" in build
    assert "PYTHONHASHSEED=0" in build
    assert "TZ=UTC" in build
    assert "LC_ALL=C.UTF-8" in build
    assert 'test "$(maturin --version)" = "maturin 1.15.0"' in build
    assert "maturin build --release --locked --compatibility manylinux_2_28 --manifest-path /src/Cargo.toml" in build
    assert att.MANYLINUX_IMAGE in workflow
    checks += 1
    print("[GREEN] closure build sees read-only /src rather than the repository and keeps exact deterministic toolchain policy")

    proof_start = workflow.index("- name: Prove RUST-016 closure wheel equals ordinary reproducible build")
    proof = workflow[proof_start:]
    assert 'python rust_016_source_closure_spec.py "$closure"' in proof
    assert 'python rust_013_reproducible_wheel_spec.py wheelhouse-repro-a wheelhouse-closure "$SOURCE_DATE_EPOCH"' in proof
    assert "cp -- wheelhouse-closure/*.whl wheelhouse-portable/" in proof
    assert "python rust_009_portable_linux_wheel_spec.py" in proof
    lower = workflow.lower()
    assert "permissions:\n  contents: read" in workflow
    for marker in (
        "id-token: write",
        "attestations: write",
        "packages: write",
        "contents: write",
        "actions/upload-artifact",
        "actions/attest",
        "maturin publish",
        "twine upload",
        "gh release",
        "softprops/action-gh-release",
        "docker push",
    ):
        assert marker not in lower, marker
    assert "does not add the closure result" in doc.lower()
    checks += 1
    print("[GREEN] closure proof reuses RUST-013/RUST-009 equality contracts without publication, OIDC, or provenance mutation")

    for name in PRODUCTION:
        assert "axven_native" not in text(name), name
    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    assert axven.CHAIN_CONFIG["smt_activation_height"] == 10_000
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2_000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5_000
    checks += 1
    print("[GREEN] production remains Python-authoritative and canonical chain identity is unchanged")

    assert checks == 5
    print("RUST-016 hermetic native source-closure policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
