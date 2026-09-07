# RUST-038 — TEST-ONLY multi-observer checkpoint gossip

RUST-038 composes the exact reviewed RUST-037 append-only rotation journal and adds a detached TEST-only observation layer with three verifier-pinned observer identities.

The contract requires at least 2-of-3 distinct signed observer reports to match the exact canonical RUST-037 final checkpoint statement. Observer IDs are unique and canonically sorted. Reports bind the checkpoint-statement digest, witness-set sequence/digest, journal digest, head-entry digest, previous-checkpoint digest, activation source commit, and `production=false`.

A validly signed observed report for a different checkpoint statement at the same witness-set sequence and same previous-checkpoint parent is rejected even when two other observers agree with the canonical checkpoint. This strict fail-closed rule favors split-view safety over availability in the TEST simulation.

This does **not** create global network gossip, durable observer transport, independent operational custody, a transparency service, production anti-rollback, HSM/TPM integration, or a production fork-discovery guarantee. All observer seeds are deterministic TEST fixtures owned by one CI producer. Production consensus remains Python-authoritative and all production decisions remain explicit future approval gates.
