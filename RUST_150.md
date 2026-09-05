# RUST-150 — CI fan-out hardening

RUST-150 hardens the journal/checkpoint CI boundary without changing production consensus or production Rust routing.

The checkpoint fixes four independent pull-request verification lanes: Axven Validation, Axven Fuzz Smoke, Axven Performance Baseline, and the active RUST-149 journal checkpoint workflow. Validation and Fuzz remain unfiltered on pull_request, Performance remains a distinct pull_request workflow, and the active native checkpoint keeps explicit rust_*.py / RUST_*.md / predecessor-workflow / self-workflow trigger coverage.

A separate RUST-150 policy workflow watches Rust checkpoint sources/docs, critical workflow files, validation/fuzz/performance inputs, and dependency locks. Its policy pins the exact reviewed workflow blobs and rejects trigger weakening, write permissions, credential persistence, unpinned checkout/setup-python actions, workflow coupling that collapses the independent gates, or removal of the RUST-149 predecessor/self trigger closure.

The mutation selftest exercises fail-closed cases for removing pull_request fan-out, adding narrow path filters to Validation/Fuzz, deleting Performance PR coverage, weakening native checkpoint path closure, enabling write permissions, or allowing checkout credentials.

This checkpoint is non-production CI policy only. It introduces no signing authority, key custody, deployment/release authority, network protocol change, consensus rule change, state-transition change, or production Rust decision authority. Production consensus remains Python-authoritative.
