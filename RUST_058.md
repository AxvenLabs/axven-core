# RUST-058 — TEST-ONLY observer-rotation-journal checkpoint monitoring

RUST-058 composes the exact reviewed RUST-057 append-only observer-rotation journal verifier and adds deterministic TEST-ONLY multi-monitor observation of its final checkpoint.

Three independent TEST-only monitors M1/M2/M3 are pinned by Ed25519 public key. A valid bundle requires a 2-of-3 quorum, and all 3/3 valid two-monitor subsets are accepted. Each signed report is domain-separated and binds the exact RUST-057 final observer-rotation-journal checkpoint SHA-256, the exact checkpoint-statement SHA-256, observer-set sequence and digest, entry count, journal and head-entry digests, previous-checkpoint parent, the exact RUST-054 observed checkpoint and statement digests carried through RUST-057, inherited journal-observer and monitor-journal checkpoint bindings, activation source commit, and `production=false`.

A valid signed report for a distinct final observer-rotation-journal checkpoint with the same observer-set sequence and the same previous-checkpoint parent is rejected fail-closed as a same-parent split view, even when a canonical quorum is otherwise present. Dedicated observed-fork evidence proves that a valid signed fork can be recognized without accepting it as canonical. RUST-057 final checkpoint bytes cannot replay as a RUST-058 monitor bundle.

The detached verifier and selftest contain no private signing or network capability. Deterministic TEST private Ed25519 seeds exist only in the producer fixture and are checked against pinned public keys. Evidence is made read-only before detached verification.

This TEST-only evidence does **not** create durable global gossip, production monitoring, production signing, key custody, HSM/TPM use, OIDC, publication, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
