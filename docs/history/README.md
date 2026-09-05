# Axven historical documentation

This directory contains documentation and checkpoint material that has been archived from the repository root without changing production behavior.

## Sections

- `checkpoints/` — historical checkpoint documents.
- `checkpoint_specs/` — historical checkpoint-spec scripts moved out of the repository root.
- `rebuild/` — historical rebuild notes and reconstruction material.
- `rust/` — archived Rust checkpoint documents. See `rust/README.md` for the Rust archive index and path-sensitive move policy.

## Archive boundary

Files under `docs/history/` are historical records, not a signal that the corresponding safety, validation, reproducibility, or security contracts are disabled. Active code, workflows, policy checks, release metadata, consensus/state-transition behavior, cryptographic rules, deployment behavior, and network behavior remain governed by their current repository locations.

Path-sensitive workflow or verifier references must be updated atomically with any future document move. Do not move release-manifest-bound, activation, canonical-operations, audit, or other current operational documents into this archive without a separate dependency review.

Production consensus remains Python-authoritative unless a separately reviewed and explicitly approved change says otherwise.
