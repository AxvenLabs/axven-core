# Axven Core

Axven Core is the reference node/wallet implementation for the canonical
`axven-devnet-2` network.

Current stage: **canonical devnet / pre-public release hardening**.

## What is implemented

- PoW chain with cumulative-chainwork fork choice
- Ed25519 (`N`) addresses
- ML-DSA-44 (`M`) addresses
- Hybrid Ed25519 + ML-DSA (`H`) authorization
- canonical input encoding and witness-separated txids
- UTXO state roots with Sparse Merkle activation path
- wallet backup/persistence and PQ-aware change
- JSON-RPC, CLI, TCP P2P, restart/replay and reorg handling
- local read-only block explorer
- Windows operator launchers

## Canonical devnet identity

- Network: `axven-devnet-2`
- Fingerprint: `ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae`
- Genesis: `a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3`

## Windows quick start

```text
1. run setup.cmd
2. run start-node1.cmd
3. run axven-console.cmd
4. run open-explorer-node1.cmd
```

The first node start creates an encrypted wallet and asks for a passphrase.

## Validation

On Windows PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\validate_windows.ps1
```

The validation suite covers real ML-DSA, wallet integration, daemon lifecycle,
TCP P2P, two-node reorg/reconnect, canonical activation records, consensus
replay, and incremental SMT.

## Security / status

This repository represents a canonical **devnet**, not a production mainnet.
RPC and explorer interfaces are loopback-only by default. Do not expose them
directly to the public Internet.

See `SECURITY.md`, `CANONICAL_OPERATION_RECORD.md`, and
`CD-003_ACTIVATION.md` for current operational/consensus records.
