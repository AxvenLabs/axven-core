# Changelog

## v0.9 canonical devnet — unreleased

### Consensus / cryptography
- canonical `axven-devnet-2` activation recorded under CD-003
- Ed25519, ML-DSA-44, and Hybrid authorization
- canonical input strictness / malformed-wire rejection
- witness-separated transaction IDs
- block-size enforcement and state-root validation
- chainwork/reorg/replay hardening

### Wallet / node
- encrypted wallet backup/persistence
- PQ-aware coin selection/change/signing
- pending UTXO tracking
- persistent chain datadir
- RPC/CLI daemon lifecycle
- real TCP P2P synchronization and propagation

### Operations / UX
- real Windows validation and two-node canonical operation record
- interactive console and Windows launchers
- local read-only explorer/API

### Not yet a mainnet release
- public Internet deployment hardening
- public seed/discovery infrastructure
- external independent security audit
- final public documentation/whitepaper
