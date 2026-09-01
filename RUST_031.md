# RUST-031 — Stdlib-only successor attestation behind the monotonic trust-state floor

RUST-030 established a byte-identical, Python-stdlib-only Ed25519 verifier for the original RUST-026 TEST-ONLY build-material trust root. RUST-028 then authorized a TEST-ONLY successor key, and RUST-029 established a sequence-1 rollback floor. RUST-031 composes those boundaries into one detached verification path.

## Contract

RUST-031 does not introduce another Ed25519 implementation. It imports the byte-identical RUST-030 verifier and reuses its RFC 8032 arithmetic, canonical signature decoding and material-evidence verification.

The RUST-031 consumer:

1. re-verifies the real RUST-025 upstream-authenticated detached build through the RUST-030 material verifier;
2. requires the original RUST-026 TEST-ONLY material envelope to verify under the pinned sequence-0 key;
3. verifies the old-key-signed RUST-028 sequence-1 transition with the same stdlib Ed25519 primitive;
4. derives and validates the exact RUST-029 sequence-1 state, including predecessor-state and transition SHA-256 bindings;
5. enforces `MINIMUM_SEQUENCE = 1`, rejecting the sequence-0 state as stale;
6. obtains the current successor key from the accepted sequence-1 state; and
7. accepts the successor material envelope only if it signs the exact same canonical RUST-026 build-material payload.

The resulting detached consumer therefore cannot accept the successor merely because its public key is present in an envelope. The successor is usable only after the old root authorizes the transition and the sequence-1 state satisfies the rollback floor.

## Detached execution

The workflow stages only the RUST-030 stdlib verifier, the RUST-031 verifier and canonical TEST-ONLY evidence/state files into the detached consumer. Verification runs with `/usr/bin/python3 -S`, `env -i`, `PYTHONNOUSERSITE=1`, no repository package path and no network operation.

The consumer has no private seed, private-key API, sealing/issuing function, subprocess/Git dependency, Axven production import or third-party Python dependency.

The fail-closed self-test rejects 11 mutation classes: stale final state, rollback transition, transition-signature mutation, predecessor digest mutation, transition digest mutation, current-key downgrade, successor key-ID substitution, successor-signature mutation, successor payload substitution, activation-source mismatch and non-canonical final-state encoding.

## Security boundary

RUST-031 proves software-level continuity from the original TEST-ONLY root to the accepted successor and binds successor material verification to the RUST-029 minimum sequence. It does not solve rollback of the verifier binary together with all persisted trust state. Production anti-rollback storage/HSM/key-management remains a separate explicit design and approval gate.

## Non-goals

RUST-031 does not add a production signing key, OIDC, artifact or attestation publication, a release, deployment, consensus or chain-identity changes, or production Rust routing.

Production consensus remains Python-authoritative. Production signing, publication, anti-rollback storage and Rust production routing remain separate explicit approval gates.
