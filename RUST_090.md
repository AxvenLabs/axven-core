# RUST-090 — TEST-ONLY RUST-089 journal checkpoint monitoring

RUST-090 composes the exact reviewed RUST-089 append-only checkpoint-monitor rotation journal verifier and adds an independent detached TEST-only 2-of-3 monitor quorum over its final signed journal checkpoint.

Three independent TEST-only monitors are pinned. Every report binds the exact RUST-089 final checkpoint SHA-256 and checkpoint-statement SHA-256 plus all 10 inherited checkpoint statement fields, yielding a 12-field canonical target. All 3/3 valid two-monitor subsets are accepted.

The target binds monitor-set sequence/digest, entry count, journal/head/parent digests, monitored checkpoint/statement digests, observed-target digest and activation source. `production=false` is mandatory throughout.

A validly signed same-parent RUST-089 checkpoint fork can be recognized as observed evidence but cannot substitute for the canonical monitor bundle. The detached selftest rejects quorum downgrade, duplicate/unsorted or unknown monitors, signature mutation, mutation of every target field, non-canonical evidence, RUST-089 checkpoint replay and signed same-parent fork substitution. The fail-closed matrix is fixed at 27/27 expected rejection cases.

Deterministic TEST private seeds exist only in the producer fixture. The verifier and selftest have no signing or network capability. CI keeps generated continuity evidence read-only, stages a 63-file verifier-only detached consumer, uses a fixed 156-path evidence manifest, and verifies under a clean `env -i` plus `/usr/bin/python3 -S` environment.

This checkpoint introduces no global gossip, durable publication, production monitor administration/signing, key custody, HSM/TPM integration, OIDC, release/deployment authority, consensus change or production Rust routing. Production consensus remains Python-authoritative.
