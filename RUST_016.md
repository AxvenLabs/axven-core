# RUST-016 — Detached signed build-input verification

RUST-016 closes one explicit limitation left by RUST-015: the reproducibility provenance authenticates SHA-256 claims for the exact build inputs, but a detached consumer previously had no copy of those source/build-policy files from which to recompute the claims.

This checkpoint carries those signed build inputs across the repository boundary and verifies them from a clean offline bundle. It remains a TEST-ONLY release-security rehearsal and does not publish artifacts or change production routing.

## Detached bundle

The detached consumer tree contains exactly 17 regular files:

- `rust_015_offline_repro_consumer_verify.py`;
- `rust_016_offline_build_input_verify.py`;
- `build-a/axven_native-0.1.0-cp313-abi3-manylinux_2_28_x86_64.whl`;
- `build-b/axven_native-0.1.0-cp313-abi3-manylinux_2_28_x86_64.whl`;
- `reproducible-provenance.json`;
- `reproducible-attestation.json`;
- eleven files below `source-inputs/`, preserving their signed repository-relative paths.

The eleven source/build-policy inputs are exactly the `build_inputs` set authenticated by the RUST-014 provenance:

1. `native/axven_native/Cargo.toml`
2. `native/axven_native/Cargo.lock`
3. `native/axven_native/src/lib.rs`
4. `requirements-native-build.lock`
5. `requirements-ci-runtime-posix.lock`
6. `rust_009_portable_linux_wheel_spec.py`
7. `rust_013_reproducible_wheel_spec.py`
8. `rust_013_reproducible_build_policy_spec.py`
9. `rust_014_reproducible_attestation.py`
10. `rust_014_reproducible_attestation_policy_spec.py`
11. `.github/workflows/native-reproducible-build.yml`

No `.git` directory is copied. The bundle contains no symlinks and CI asserts both the total 17-file count and the exact 11-file source-input count before verification.

## Layered verification

RUST-016 deliberately composes with the already detached RUST-015 verifier instead of duplicating its signature and wheel policy.

The consumer first requires RUST-015 verification to succeed. That establishes:

- canonical signed RUST-014 provenance and envelope;
- the pinned TEST-ONLY Ed25519 verification policy;
- two canonical portable wheels;
- byte-for-byte build reproducibility;
- artifact hash and byte-length binding;
- source-epoch ZIP timestamp policy;
- exact build-input claim key set;
- `production_consensus: python`.

Only after that authenticated layer passes does RUST-016 validate the supplied `source-inputs/` tree.

## Build-input filesystem contract

The RUST-016 verifier requires the source-input root to be a real directory rather than a symlink. It recursively rejects symlinks, special filesystem objects, unexpected files, unexpected directories, missing files, and path relocation.

The only accepted regular files are the eleven signed relative paths above. For every file the verifier recomputes SHA-256 from bytes and requires exact equality with the corresponding authenticated `build_inputs` value in the signed provenance.

This turns the RUST-014 `build_inputs` map from detached signer claims into independently recomputable file-content claims for the supplied bundle.

## What RUST-016 does not prove

RUST-016 does **not** claim that the supplied source-input files are, by themselves, a cryptographic proof of the claimed Git commit tree. The source commit remains an authenticated provenance claim because the detached bundle intentionally contains no Git object database.

It also does not perform a third source rebuild. Git object/tree verification, cross-provider reproducible rebuilds, protected production signing, transparency logging, and artifact publication remain separate future gates.

## Fail-closed mutation contract

The detached self-test requires rejection of eight classes of mutation:

1. source-input file byte mutation;
2. missing signed input;
3. extra unsigned input;
4. source-root symlink substitution;
5. individual input symlink substitution;
6. signed-path relocation/confusion;
7. authenticated `build_inputs` claim mutation;
8. upstream wheel byte mutation.

The original wheels, provenance, envelope, and source-input tree must remain byte-identical after the mutation suite and must verify again.

## Isolation and privilege boundary

The RUST-016 detached verifier has no Axven production import, RUST-014 producer import, Git dependency, GitHub environment dependency, Docker dependency, HTTP/network client, or subprocess dependency. Its only project-module dependency is the already detached RUST-015 consumer verifier copied into the same clean directory.

CI executes verification, mutation testing, and final reverification under `env -i` with only a minimal Python path and UTF-8 controls preserved.

The workflow remains `contents: read` only. RUST-016 does not upload an Actions artifact, publish a package, create a GitHub Release, request OIDC, write a GitHub attestation, use a production signing credential, push a container, deploy code, or enable production Rust routing.

## Consensus boundary

Production remains Python-authoritative. RUST-016 changes no production file and does not alter chain identity, genesis, monetary rules, P2P protocol, SMT/PQ activation, ML-DSA behavior, wallet-key semantics, or transaction/block signature-acceptance rules.
