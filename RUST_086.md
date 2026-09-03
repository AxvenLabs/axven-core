# RUST-086 — TEST-ONLY observation of the RUST-085 final monitor-rotation journal checkpoint

RUST-086 composes the exact reviewed RUST-085 append-only checkpoint-monitor rotation journal verifier and adds an independent TEST-only 2-of-3 observer quorum over its final checkpoint.

The complete RUST-085 verifier chain is executed before observer evidence can be accepted. The underlying M3/M4/M5 final journal-checkpoint signatures are therefore revalidated; independent observation does not replace or weaken the monitor quorum.

Three deterministic TEST-only observer identities O1/O2/O3 are pinned in the verifier. Producer private seeds exist only in the fixture. Any two observers form a valid quorum, so all 3/3 valid two-observer subsets must verify.

Each signed observation binds the exact RUST-085 final checkpoint SHA-256, checkpoint-statement SHA-256, monitor-set sequence and digest, entry count, journal and head-entry digests, previous checkpoint parent, monitored checkpoint and statement digests, observed-target digest and activation source commit. Evidence is canonical JSON and `production=false`.

If an observer presents a different validly signed RUST-085 checkpoint with the same monitor-set epoch and previous-checkpoint parent, the observer layer rejects the evidence as a same-parent split-view/fork substitution rather than choosing either branch.

The detached selftest covers 25/25 fail-closed cases: below-threshold and threshold downgrade, duplicate/unsorted/unknown observers, signature/envelope/schema/production mutations, source/sequence/parent substitution, journal/head/set/count mutation, checkpoint and checkpoint-statement substitution, monitored checkpoint and statement substitution, target-digest mutation, non-canonical JSON and a validly signed cross-observer same-parent fork.

CI regenerates the reviewed fixture chain, makes evidence read-only, stages a verifier-only detached consumer, uses a fixed 145-path evidence manifest, and verifies under a clean `env -i` plus `/usr/bin/python3 -S` environment. No observer private key is staged in that consumer.

This checkpoint does not introduce global gossip, durable publication, production observation/signing, production key custody, HSM/TPM integration, OIDC, release/deployment authority, consensus changes or production Rust routing. Production consensus remains Python-authoritative.
