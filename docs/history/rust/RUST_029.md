# RUST-029 — Monotonic TEST-ONLY trust state and rollback floor

RUST-028 proved a cryptographically authorized transition from the original RUST-026 TEST-ONLY attestation key to the RUST-028 TEST-ONLY successor. RUST-029 adds the consumer-side state machine needed to remember that transition and reject stale/replayed trust state.

## Contract

The checkpoint defines canonical `axven-native-trust-state-v1` state objects.

The pinned genesis state is sequence `0` and contains the original RUST-026 TEST-ONLY key. Applying the RUST-028 sequence-1, old-key-signed transition produces sequence `1` containing the RUST-028 successor. The resulting state binds:

- current sequence, scope, key ID and public key;
- activation source commit;
- SHA-256 of the exact predecessor state;
- SHA-256 of the exact authorized transition;
- `production=false`.

A verification-only consumer pins a minimum accepted sequence of `1`. After the RUST-028 transition has been accepted, that consumer rejects the sequence-0 genesis state as stale, rejects replaying the sequence-1 transition onto sequence 1, and rejects key/digest/source substitutions.

The detached verifier contains no private seed, `Ed25519PrivateKey`, sealing/issuing capability, Axven producer import, Git dependency or network operation.

## Rollback boundary

RUST-029 proves fail-closed monotonic state-transition logic and a software-enforced minimum sequence. It does **not** claim that an attacker who can roll back the verifier binary and every copy of consumer state has been defeated. A production implementation would need to keep its accepted sequence/state digest in a storage or policy boundary that cannot be silently rolled back with the application itself.

That production storage/key-management decision remains outside this checkpoint and requires separate explicit review.

## Failure contract

The mutation suite rejects stale final state, replay, predecessor hash mutation, transition hash mutation, current-key downgrade, transition from-key substitution, successor-key substitution, transition signature mutation, activation-source mismatch, and non-canonical state encoding.

## Non-goals

RUST-029 does not add a production key, OIDC, artifact or attestation publication, release machinery, deployment, chain/consensus changes, or production Rust routing.

Production consensus remains Python-authoritative. Production signing, artifact publication and Rust production routing remain separate explicit approval gates.
