# RUST-039 — TEST-ONLY observer-set rotation and revocation continuity

RUST-039 composes the exact reviewed RUST-038 multi-observer checkpoint gossip verifier and adds a TEST-only observer-set rotation from `O1/O2/O3` to `O2/O3/O4`, with O1 explicitly revoked.

The canonical transition is bound to the exact predecessor observer-set SHA-256, the exact canonical RUST-037 final checkpoint-statement SHA-256, the activation source commit, successor observer-set sequence `1`, threshold `2`, and `production=false`. Any valid 2-of-3 predecessor observers may authorize the exact transition. The successor checkpoint observation then uses a distinct domain and schema bound to the exact successor observer-set hash and sequence.

All 3/3 valid predecessor two-observer authorization subsets and all 3/3 valid successor two-observer subsets are accepted. Revoked-O1 resurrection, threshold downgrade, stale epoch replay, old RUST-038 bundle replay, source/digest substitution, noncanonical evidence, and a validly signed same-parent successor split view fail closed.

This remains a deterministic TEST-only continuity simulation. It does **not** create independent observer administration, durable observer transport/publication, global gossip, real compromise recovery, HSM/TPM custody, production anti-rollback, or a production fork-discovery guarantee. Production consensus remains Python-authoritative and all production decisions remain explicit future approval gates.
