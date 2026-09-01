# RUST-007 — Native wheel package gate

RUST-007 proves that the dormant `axven_native` crate can be turned into a Python wheel, inspected as an archive, installed without network access, and imported from a clean temporary location on Linux, Windows, and macOS.

This checkpoint is **build/package-test only**. It does not upload, publish, release, commit, or otherwise distribute a generated wheel. It does not add a native wheel to Axven's canonical release and does not route production consensus through Rust.

## Build frontend trust

The build frontend is exactly `maturin==1.15.0`. CI installs it from platform wheels only with `pip --require-hashes --only-binary=:all: --no-deps` using `requirements-native-build.lock`. The committed hashes cover the compatible official PyPI wheels for the CI matrix.

The native crate itself remains Cargo-lockfile bound and is built with Rust `1.98.0`, CPython `3.13.15`, `--release`, and `--locked`.

## Wheel integrity contract

For each OS matrix runner, exactly one wheel must be produced. Before installation the test verifies:

- the wheel filename identifies `axven_native` version `0.1.0`;
- ZIP member names are relative and contain no parent traversal;
- exactly one native extension payload exists;
- `METADATA`, `WHEEL`, and `RECORD` are present under the expected dist-info directory;
- metadata declares `Name: axven-native`, `Version: 0.1.0`, and the pinned Python compatibility range;
- the wheel is not marked pure-Python;
- every archived file is covered by `RECORD`, and every non-RECORD entry's SHA-256 and size match its RECORD declaration.

The wheel's complete SHA-256 and byte length are printed as diagnostic evidence. They are deliberately not committed as cross-platform constants because platform-native binaries differ and reproducible-build hardening is a separate checkpoint.

## Clean-install contract

The wheel is installed by direct local path with `--no-index --no-deps` into a temporary target directory. A fresh Python subprocess running outside the repository imports only that installed target and must:

- report `boundary_version() == "rust-001"`;
- reproduce the fixed RUST-002 one-leaf Sparse-Merkle root exactly;
- reject duplicate-outpoint input fail-closed.

Production Python modules are independently checked to remain free of `axven_native` imports.

## Distribution and consensus boundary

The workflow uses `contents: read`, does not persist checkout credentials, contains no upload/publish action, and does not retain wheel artifacts. `pyproject.toml`, `build_release_package.py`, `release_manifest.json`, installer behavior, and runtime provenance are not changed in this checkpoint.

No chain identity, genesis, reward/monetary rule, P2P protocol, SMT/PQ activation height, ML-DSA behavior, wallet-key semantics, or signature-acceptance semantics change. `expected_state_root()` remains Python-authoritative.

A later checkpoint must design authenticated native artifact provenance and canonical release integration before any binary can be shipped. Production consensus routing remains a separate explicit approval gate.