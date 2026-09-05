#!/usr/bin/env python3
"""RUST-013: static contract for the reproducible portable build rehearsal."""
from __future__ import annotations

from pathlib import Path

import axven

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/native-reproducible-build.yml"
PRODUCTION = ("axven.py", "core.py", "p2p.py", "rpc.py", "wallet.py", "axven_core.py")
MANYLINUX_IMAGE = (
    "quay.io/pypa/manylinux_2_28_x86_64@"
    "sha256:443eabd378e140996780a772e12c1a1ef10551da933fe76d74a1bab61f68a7b7"
)


def text(path: Path | str) -> str:
    target = path if isinstance(path, Path) else ROOT / path
    return target.read_text(encoding="utf-8")


def main() -> None:
    checks = 0
    workflow = text(WORKFLOW)
    source = text("rust_013_reproducible_wheel_spec.py")
    doc = text("docs/history/rust/RUST_013.md")

    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert '${{ github.event.pull_request.head.sha || github.sha }}' in workflow
    assert 'python-version: "3.13.15"' in workflow
    assert "rustup toolchain install 1.98.0 --profile minimal" in workflow
    assert MANYLINUX_IMAGE in workflow
    assert "docker image inspect" in workflow
    assert 'git rev-parse HEAD' in workflow
    assert 'git show -s --format=%ct "$AXVEN_SOURCE_SHA"' in workflow
    checks += 1
    print("[GREEN] exact source, host verifier, Rust toolchain, immutable image, and source-derived epoch are pinned")

    for marker in (
        "SOURCE_DATE_EPOCH",
        "CARGO_INCREMENTAL=0",
        "PYTHONHASHSEED=0",
        "TZ=UTC",
        "LC_ALL=C.UTF-8",
        "CARGO_TARGET_DIR=/work/.rust013-target-a",
        "CARGO_TARGET_DIR=/work/.rust013-target-b",
        "wheelhouse-repro-a",
        "wheelhouse-repro-b",
        ".rust013-tools-a",
        ".rust013-tools-b",
        "sleep 2",
    ):
        assert marker in workflow, marker
    assert workflow.count("docker run --rm") == 2
    assert workflow.count("maturin build --release --locked --compatibility manylinux_2_28") == 2
    checks += 1
    print("[GREEN] build A/B use separate containers, targets, tool dirs, wheelhouses, and deterministic environment controls")

    assert "python rust_013_reproducible_wheel_spec.py" in workflow
    assert workflow.count("python rust_009_portable_linux_wheel_spec.py") == 2
    for marker in (
        "complete wheel archives are byte-for-byte identical",
        "ZIP member order/metadata are identical",
        "every wheel member payload is identical",
        "RUST-013 reproducible portable wheel contract: 5/5 GREEN",
        "expected_zip_time",
        "first_byte_difference",
    ):
        assert marker in source, marker
    checks += 1
    print("[GREEN] byte identity, archive metadata, entry payloads, and both RUST-009 portable contracts are enforced")

    lower = workflow.lower()
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
    assert "not yet claim cross-provider" in doc.lower()
    assert "does not retroactively change the rust-011 provenance" in doc.lower()
    checks += 1
    print("[GREEN] reproducibility rehearsal has no publication/OIDC privilege and does not silently change signed provenance semantics")

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
    print("RUST-013 reproducible build policy contract: 5/5 GREEN")


if __name__ == "__main__":
    main()
