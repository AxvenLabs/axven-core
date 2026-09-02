# RUST-040 — TEST-ONLY multi-step observer-set rotation and cumulative revocation

RUST-040 composes the exact reviewed RUST-039 observer-set rotation verifier and extends the TEST-only observer continuity chain from `O1/O2/O3 -> O2/O3/O4` to `O3/O4/O5` at observer-set sequence `2`.

The second transition is authorized by any valid 2-of-3 predecessor observers from `O2/O3/O4`, binds the exact predecessor observer-set digest, the exact RUST-039 rotation-record SHA-256, the exact RUST-039 successor-bundle SHA-256, the canonical RUST-037 checkpoint-statement digest, the activation source commit, and `production=false`. Cumulative revocation becomes `[O1, O2]` and the final set is exactly `O3/O4/O5` with threshold `2`.

All 3/3 valid predecessor two-observer authorization subsets and all 3/3 valid final two-observer subsets are accepted. Revoked O1/O2 resurrection, cumulative-revocation truncation, predecessor-record substitution, old RUST-039 successor replay, epoch rollback, noncanonical evidence, and a validly signed same-parent final split view fail closed.

This remains a deterministic TEST-only continuity simulation. It does **not** create independent observer administration, durable observer transport/publication, global gossip, real compromise recovery, HSM/TPM custody, production anti-rollback, or a production fork-discovery guarantee. Production consensus remains Python-authoritative and all production decisions remain explicit future approval gates.
