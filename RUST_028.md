# RUST-028 — Stdlib-only detached Ed25519 material verifier

RUST-027 physically separated the TEST-ONLY producer/sealer from the detached build-material consumer, but the consumer still depended on the external `cryptography` runtime for Ed25519 verification.

RUST-028 removes that final verifier-side package dependency.

## Stdlib-only verification

The RUST-028 consumer is a standalone Python verifier whose imports are limited to the Python standard library. It independently pins the RUST-026 material/envelope schemas, domain, key id, public key, builder identity, upstream Rust distribution identity and expected wheel name.

Ed25519 verification is implemented from the RFC 8032 verification equation using integer arithmetic and `hashlib.sha512`. The implementation enforces canonical point encodings, rejects invalid points, rejects `S >= L`, and checks `[S]B = R + [k]A` against the independently pinned public key. A pinned RFC 8032 empty-message test vector is executed before any Axven attestation is accepted, and a mutated vector must be rejected.

The detached consumer contains no TEST_SEED, Ed25519 private-key API, sealing function, `cryptography` import, third-party package import, producer-module import, Axven import, subprocess or Git dependency.

## Material verification

As in RUST-027, acceptance also recomputes the final wheel identity, upstream Rust archive hash, normalized RUST-023 toolchain manifest identity, Cargo/build lock hashes, dependency closure and vendor closure before accepting the signature-bound RUST-026 statement.

The workflow first reproduces RUST-025 and creates the TEST-ONLY RUST-026 materials with the producer side. It then stages exactly three consumer files (`verifier.py`, `materials.json`, `attestation.json`) and invokes `/usr/bin/python3 -S` under `env -i` from `/tmp`, with no repository Python site-packages available to the verifier.

The consumer fail-closed suite rejects the same ten external evidence/signature substitutions covered by RUST-027 and then re-verifies the pristine statement.

## Boundary

RUST-028 is supply-chain verification hardening only. It does not upload or publish artifacts or attestations, enable OIDC, introduce a production signing key, create a release, deploy code, change chain/consensus semantics or route production execution through Rust.

Production consensus remains Python-authoritative. Production signing, publication and Rust routing remain separate explicit approval gates.
