# RUST-050 — TEST-ONLY journal-observer-journal checkpoint monitoring

RUST-050 composes the exact reviewed RUST-049 append-only journal-observer rotation journal verifier and adds a deterministic TEST-only multi-monitor split-view discovery layer over the final RUST-049 journal-observer checkpoint.

Three pinned TEST-only journal-monitor identities (`JM1/JM2/JM3`) independently sign observations of the exact canonical RUST-049 final journal-observer checkpoint. Acceptance requires at least 2-of-3 distinct valid Ed25519 reports. Every report binds the exact journal-observer checkpoint digest, journal-observer set sequence/digest, entry count, journal digest, head-entry digest, previous-checkpoint digest, the exact canonical RUST-045 monitor-journal checkpoint digest and checkpoint-statement digest inherited through RUST-049, the activation source commit, and `production=false`.

The canonical RUST-049 final checkpoint is first revalidated through the full reviewed RUST-049 verifier chain. Monitoring does not replace or weaken the underlying journal-observer checkpoint signatures.

A valid signed report for a distinct checkpoint with the same observer-set sequence and same previous-checkpoint parent is rejected fail-closed as an observed journal-monitor same-parent journal-observer-journal fork, even when two other journal monitors report the canonical checkpoint. This strict fail-closed rule favors split-view safety over availability.

The availability contract accepts all 3/3 valid two-monitor subsets. The detached verifier and selftest contain no private signing or network capability. Deterministic TEST private Ed25519 seeds exist only in the producer fixture and are checked against the reviewed public-key pins.

This TEST-only evidence does **not** create independent journal-monitor administration, durable network transport, global gossip, transparency publication, production signing, key custody, HSM/TPM use, OIDC, release/deployment authority, production anti-rollback guarantees, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
