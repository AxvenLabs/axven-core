# RUST-030 — Stdlib-only detached monotonic trust consumer

RUST-029 established a verification-only monotonic TEST-ONLY trust-state machine and a software rollback floor at sequence `1`, but its detached verifier still imports the third-party `cryptography` runtime for Ed25519 verification.

RUST-030 removes that runtime dependency from the detached trust-state consumer without weakening the RUST-029 floor.

## Contract

The detached RUST-030 consumer uses only the Python standard library. It implements the verification side of RFC 8032 Ed25519 arithmetic, pins the RUST-026 TEST-ONLY predecessor public key and the RUST-028 TEST-ONLY successor public key, and verifies the exact RUST-028 -> RUST-029 trust chain.

Before accepting Axven trust evidence it runs RFC 8032 test vector 1 (empty message). The valid vector must verify and a one-bit signature mutation must fail. Encoded Ed25519 points must be canonical, the `S` scalar must be below the group order, and the public key plus signature `R` point must be non-identity members of the prime-order subgroup.

The consumer then requires:

- canonical `axven-native-trust-state-v1` genesis and final state;
- canonical `axven-native-trust-transition-v1` sequence-1 transition;
- canonical `axven-native-trust-transition-envelope-v1` envelope;
- the old TEST-ONLY key as the transition signer;
- the RUST-028 successor as the resulting current key;
- exact activation-source binding;
- exact predecessor-state and transition SHA-256 chaining;
- `production=false`;
- minimum accepted sequence `1`.

Sequence `0` is therefore still rejected as stale by the detached stdlib-only consumer.

## Differential and detached verification

CI first generates the existing TEST-ONLY transition fixture and verifies it with the cryptography-backed RUST-029 verifier. That producer-side baseline is not copied into the detached consumer.

The detached directory contains exactly five regular files: the RUST-030 verifier plus genesis, transition, envelope and final-state JSON. Verification and the fail-closed suite run under `env -i` with `/usr/bin/python3 -S`, no site-packages path, no repository checkout, no Git metadata and no network operation.

The mutation contract retains the ten RUST-029 rejection classes: stale state, replay, predecessor digest mutation, transition digest mutation, current-key downgrade, from-key substitution, successor substitution, signature mutation, activation-source mismatch and non-canonical state.

## Boundary

The pure-Python Ed25519 implementation is a verification-only detached CI consumer. It is **not** used by Axven consensus, wallets, transaction authorization, production signing or production artifact verification policy.

RUST-030 still does not solve rollback of the verifier binary together with every external copy of trust state. A rollback-resistant external storage/policy boundary remains a separate explicit production design decision.

## Non-goals

RUST-030 adds no production key, no OIDC, no artifact/attestation publication, no release machinery, no deployment, no chain/consensus change and no production Rust routing.

Production consensus remains Python-authoritative. Production signing, artifact publication, rollback-resistant external trust storage and Rust production routing remain separate explicit approval gates.
