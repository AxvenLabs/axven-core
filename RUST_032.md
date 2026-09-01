# RUST-032 — TEST-ONLY external monotonic-floor interface

RUST-031 composes the stdlib-only material verifier with the sequence-1 TEST-ONLY trust-state transition, but its rollback floor still lives in software. If an attacker can roll back the verifier binary together with every persisted copy of trust state, the software-only floor can be rolled back too.

RUST-032 adds a deliberately narrow **TEST-ONLY external-floor interface simulation**. It does not claim to solve production rollback resistance and it does not introduce an HSM, TPM, transparency log, remote service, production key, or deployment dependency.

## Contract

The RUST-032 detached consumer receives four runtime inputs: the already-accepted final trust state, an external floor record, the expected source commit, and a required floor sequence supplied by the outer harness.

The required floor value is not compiled into the RUST-032 verifier. The external floor record is staged outside the detached consumer directory, marked read-only, and is never copied into the consumer bundle. The verifier accepts only canonical `axven-native-external-monotonic-floor-v1` records from the TEST-ONLY simulator and requires:

- the external sequence to be at least the runtime-required floor;
- the accepted trust state to remain exactly on the reviewed RUST-031 sequence/key/public-key floor;
- the accepted trust-state sequence to be at least the external sequence;
- exact scope, key ID, public key, activation source and state SHA-256 binding;
- canonical JSON and `production=false` on both state and floor evidence.

This means a stale state cannot be accepted merely by replacing files inside the detached consumer while the independently supplied floor remains advanced.

## Detached simulation

CI derives the canonical RUST-031 sequence-1 state shape using the existing reviewed RUST-030/RUST-031 modules, writes the state into a detached consumer fixture, and writes the floor to `/tmp/axven-rust032-external-floor.json` outside that consumer. The floor is chmod `0444` before verification.

The consumer runs with `/usr/bin/python3 -S` under `env -i`. It contains only the RUST-030 verifier, RUST-031 verifier, RUST-032 wrapper, and the final-state fixture. It contains no external-floor file, private seed, private-key API, sealing/issuing code, Git metadata, network client, Axven production import, or third-party Python dependency.

The fail-closed contract covers 11 mutations: runtime floor advance beyond stored floor, floor downgrade, stale final state, state-digest mutation, key-ID mutation, public-key mutation, activation-source mismatch, production-floor substitution, provider substitution, non-canonical floor encoding, and non-canonical state encoding.

## Security boundary

RUST-032 tests the **consumer interface to an independent monotonic source**. The TEST-ONLY simulator is not rollback-resistant storage. An attacker able to roll back the verifier, the outer launcher, and the external-floor provider together is still outside this checkpoint's protection.

A real production anti-rollback mechanism—such as hardware-backed monotonic state, independently administered transparency infrastructure, or another externally durable trust anchor—remains a separate explicit design and approval gate.

## Non-goals

RUST-032 does not add production signing, OIDC, artifact/attestation publication, release/deployment, chain/consensus changes, DNS/website changes, production anti-rollback storage, or production Rust routing.

Production consensus remains Python-authoritative.
