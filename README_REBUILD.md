# Axven v0.9 Rebuild — Checkpoint 0

Reconstructed from the preserved architecture and surviving W-003 executable contract.

Included now:
- canonical CHAIN_CONFIG / config fingerprint / genesis miner identity
- N/M/H address primitives and H1/H2 output gate
- witness-separated transaction commitment / txid
- canonical input encoding + total TxInput deserialization
- Ed25519 / ML-DSA-44 / Hybrid signer primitives
- downgrade-proof verify_input
- WalletIdentity + PQ-aware change policy
- surviving wallet_integration_spec_test.py

Next checkpoint: rebuild Blockchain + Mempool + StateStore APIs required by W-003.


Checkpoint 3 adds an incremental Sparse Merkle mirror and proof verification without changing activation status or CHAIN_CONFIG.


Checkpoint 6 introduces the first Bitcoin-Core-like composition layer: chain + mempool
+ wallet orchestration + mining + P2P under `AxvenCore`, with a localhost-only JSON-RPC
surface and CLI skeleton.  Consensus remains unchanged.


Checkpoint 7 makes Axven Core service-shaped: encrypted wallet persistence, persistent
chain data directory, a long-running `axven-core run` daemon, and separate `axven-cli`
RPC client.  This avoids losing in-memory mempool transactions in one-shot CLI
processes.


Checkpoint 8 hardens the live daemon lifecycle: clean shutdown, persistent restart,
simultaneous RPC/P2P operation, post-restart mining, reconnect/catch-up, and
fail-closed wallet decryption.
