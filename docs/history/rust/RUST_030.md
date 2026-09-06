# RUST-030 — Byte-identical stdlib-only detached Ed25519 material consumer

RUST-027 separated the RUST-026 TEST-ONLY build-material producer/sealer from detached consumer verification. RUST-030 adopts the independent stdlib-only verifier that was previously developed in the superseded PR #281, without rewriting its cryptographic implementation.

## Byte-identical carry-forward

The verifier is carried forward byte-for-byte from the reviewed #281 blob `0688cac21315533a3ff0fd760d28a44a9c897a6f` into `rust_030_stdlib_material_verify.py`.

This is deliberate: the RFC 8032 / Ed25519 arithmetic is not mechanically renumbered or reformatted merely to change checkpoint labels. Historical `RUST-028` diagnostic strings inside that verifier therefore remain intact and identify the original implementation revision. RUST-030 policy independently checks the exact Git blob identity before the verifier is trusted.

## Verification boundary

The carried verifier uses only the Python standard library. It independently pins the RUST-026 material/envelope schemas, domain, key ID, public key, builder identity, upstream Rust distribution identity and expected wheel name.

Ed25519 verification implements the RFC 8032 verification equation using integer arithmetic and `hashlib.sha512`. It enforces canonical point encodings, rejects invalid points, rejects `S >= L`, and checks `[S]B = R + [k]A`. A pinned RFC 8032 empty-message known-answer vector is accepted and a mutated vector must be rejected.

The detached consumer has no TEST_SEED, Ed25519 private-key API, sealing function, `cryptography` import, third-party package import, producer-module import, Axven import, subprocess or Git dependency.

## Material verification

The workflow first reproduces the RUST-025 upstream-authenticated fully detached native build and creates the TEST-ONLY RUST-026 material statement. It then:

1. verifies the statement with the existing RUST-027 `cryptography`-backed verification-only consumer;
2. verifies the exact same statement with the byte-identical stdlib-only consumer;
3. stages only `verifier.py`, `materials.json` and `attestation.json` into a detached `/tmp` consumer;
4. runs that consumer under `env -i` with `/usr/bin/python3 -S`, no user site and no repository Python package path;
5. runs the existing 10/10 fail-closed external evidence/signature mutation contract; and
6. re-verifies pristine evidence after mutation testing.

The consumer recomputes final wheel identity, upstream Rust archive hash, normalized RUST-023 toolchain manifest identity, Cargo/build lock hashes, dependency closure and vendor closure before accepting the signature-bound RUST-026 statement.

## Non-goals

RUST-030 is verification-side supply-chain hardening only. It does not upload or publish artifacts or attestations, enable OIDC, introduce a production signing key, create a release, deploy code, change chain identity or consensus semantics, or route production execution through Rust.

Production consensus remains Python-authoritative. Production signing, publication and Rust production routing remain separate explicit approval gates.
