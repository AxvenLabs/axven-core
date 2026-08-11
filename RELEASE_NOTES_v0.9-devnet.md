# Axven Core v0.9 — Canonical Devnet Preview

This release packages the activated `axven-devnet-2` reference implementation
for reproducible local/devnet operation.

Highlights:
- real Ed25519 + ML-DSA-44 + Hybrid authorization paths;
- wallet migration/signing/persistence;
- chainwork fork choice, reorg and replay validation;
- TCP P2P synchronization and transaction/block propagation;
- canonical Windows two-node operation verified;
- interactive console and local read-only explorer.

Canonical identity:
- chain: `axven-devnet-2`
- fingerprint: `ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae`
- genesis: `a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3`

Important: this is a devnet preview, not a production mainnet release. It has
not received an independent security audit and should not be presented as
production-safe.
