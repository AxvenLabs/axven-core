# Checkpoint 21 — Canonical Operation Record

Status: **REAL CANONICAL OPERATION VERIFIED**

## Canonical identity
- chain_id: `axven-devnet-2`
- CONFIG_FINGERPRINT: `ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae`
- genesis_hash: `a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3`

## Real Windows operation evidence

The canonical Node 1 was started from the activated Checkpoint 20 package and
reported:

- height: `0`
- tip: genesis hash
- RPC: `127.0.0.1:18443`
- P2P: `127.0.0.1:18444`

The first post-activation canonical block was mined successfully:

- block height: `1`
- block hash: `00654a3a90e5d24735d2baa39143e6f0144826caf4daf83b4fdc47beb6b92580`
- chainwork after block: `512`

A second independent canonical node was then started with a separate wallet and
separate ports:

- RPC: `127.0.0.1:18453`
- P2P: `127.0.0.1:18454`

Node 2 synchronized exactly one block from Node 1 over real TCP P2P:

- accepted: `1`
- resulting height: `1`
- resulting tip: `00654a3a90e5d24735d2baa39143e6f0144826caf4daf83b4fdc47beb6b92580`
- resulting chainwork: `512`

Both nodes were stopped through the graceful RPC shutdown path.

Node 1 was restarted from disk and reported:

- height: `1`
- tip: `00654a3a90e5d24735d2baa39143e6f0144826caf4daf83b4fdc47beb6b92580`
- chainwork: `512`
- mempool_size: `0`
- wallet_loaded: `true`

This proves the first canonical devnet-2 block survived persistence/restart and
remained identical to the block independently accepted by Node 2.

## Result

**CANONICAL DEVNET OPERATION VERIFIED**

Activation remains executed. No CHAIN_CONFIG/genesis/consensus rule was changed
in Checkpoint 21.
