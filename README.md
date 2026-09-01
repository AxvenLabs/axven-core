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
- attested Windows and Linux/macOS operator runtime paths

## Canonical devnet identity

- Network: `axven-devnet-2`
- Fingerprint: `ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae`
- Genesis: `a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3`

## Hardened first setup

Do not bootstrap Axven with ambient `pip`, an unconstrained editable install, or
an execution-policy bypass. The repository validators install only the reviewed,
hash-locked dependency artifacts and require the supported Python runtime.

Windows:

```text
1. install exact Python 3.13.15
2. run setup.cmd
3. run start-node1.cmd
4. run axven-console.cmd
5. run open-explorer-node1.cmd
```

`setup.cmd` delegates to the hardened Windows validator. It does not require or
request `Set-ExecutionPolicy ... Bypass`.

Linux/macOS:

```bash
# exact Python 3.13.15 is required
bash validate_linux_macos.sh
# operator commands must pass the POSIX provenance preflight
bash axven-posix.sh core --datadir ./axven-data run --rpc-port 18443 --p2p-port 18444
bash axven-posix.sh cli status
```

`validate_linux_macos.sh` stamps the validated POSIX runtime receipt only after
doctor, full validation, and the SEC-076+ security tail pass. `axven-posix.sh`
checks that receipt before the first operator Python process. If the receipt is
missing or stale, rerun the validator; do not bypass the preflight.

Do not replace these paths with `pip install --upgrade pip`, `pip install -e .`,
direct `.venv/bin/python` operator commands, or another ambient
dependency-resolution command.

The first node start creates an encrypted wallet and asks for a passphrase.

## Validation

The hardened validators run dependency integrity checks, the Axven doctor, full
validation, and the SEC-076+ security tail. Both Windows and POSIX validation
maintain platform-specific validated runtime-provenance receipts used by their
operator launch paths.

The validation suite covers real ML-DSA, wallet integration, daemon lifecycle,
TCP P2P, two-node reorg/reconnect, canonical activation records, consensus
replay, and incremental SMT.

## Security / status

This repository represents a canonical **devnet**, not a production mainnet.
RPC and explorer interfaces are loopback-only by default. Do not expose them
directly to the public Internet.

See `SECURITY.md`, `CANONICAL_OPERATION_RECORD.md`, and
`CD-003_ACTIVATION.md` for current operational/consensus records.
