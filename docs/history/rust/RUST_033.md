# RUST-033 — TEST-ONLY signed external-floor witness

RUST-032 moves the monotonic floor outside the detached consumer and binds it to the exact accepted RUST-031 trust state, but its simulated external-floor record is not independently authenticated.

RUST-033 adds a narrow **TEST-ONLY signed external-floor witness**. A dedicated deterministic TEST-ONLY witness key signs the canonical external-floor record under a separate domain. The detached consumer pins only the witness public key and verifies the signature with the already-reviewed stdlib-only Ed25519 implementation.

## Contract

The RUST-033 consumer first re-applies the complete RUST-032 external-floor verification. It then requires a canonical `axven-native-external-floor-witness-envelope-v1` envelope with:

- algorithm `ed25519`;
- key ID `rust-033-test-only-floor-witness-v1`;
- payload type `application/vnd.axven.native-external-monotonic-floor.v1+json`;
- SHA-256 of the exact canonical external-floor bytes;
- an Ed25519 signature over a dedicated `AXVEN_NATIVE_EXTERNAL_FLOOR_WITNESS_V1` domain-separated message.

The public key is independently pinned in the verifier. The witness envelope cannot supply or replace the trusted public key.

## Detached simulation

CI creates the canonical RUST-031 sequence-1 state and RUST-032 external floor, then signs the floor with a deterministic **TEST-ONLY** fixture seed. The seed exists only in the producer step; it is not staged into the detached consumer.

The floor record and its witness envelope remain outside the detached consumer directory and are chmod `0444`. The consumer bundle contains only the RUST-030, RUST-031, RUST-032 and RUST-033 verification modules plus the final-state fixture.

Detached verification runs with `/usr/bin/python3 -S` under `env -i`, with no site-packages, Git metadata, network client, Axven production import, private-key API, signing function, or producer seed.

The fail-closed contract covers 11 mutation classes: witness signature, payload digest, key ID, payload type, algorithm and schema substitution; non-canonical witness encoding; floor-provider substitution; floor downgrade; activation-source mismatch; and floor byte mutation.

## Security boundary

This checkpoint authenticates the TEST-ONLY external-floor record to a separately pinned witness key. It **does not provide durable rollback resistance**: the witness producer, outer launcher, runtime-required floor, and external storage are still simulated inside CI and can theoretically be rolled back together by an attacker controlling that entire environment.

A production witness service, hardware-backed monotonic state, independently administered transparency infrastructure, threshold/quorum policy, production signing key, and operational key custody remain separate explicit design and approval gates.

## Non-goals

RUST-033 does not add production signing, OIDC, artifact/attestation publication, release/deployment, chain/consensus changes, production anti-rollback storage, or production Rust routing.

Production consensus remains Python-authoritative.
