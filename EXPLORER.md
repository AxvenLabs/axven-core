# Axven Explorer — Checkpoint 23

Checkpoint 23 adds a local, read-only explorer/API layer to the canonical
Axven devnet-2 node. It does not change consensus.

When Node 1 is running:
- Explorer UI: `http://127.0.0.1:18445`

Node 2:
- Explorer UI: `http://127.0.0.1:18455`

Windows shortcuts:
- `open-explorer-node1.cmd`
- `open-explorer-node2.cmd`

## Read-only API

- `GET /api/summary`
- `GET /api/blocks?limit=20`
- `GET /api/block/<height-or-hash>`
- `GET /api/tx/<txid>`
- `GET /api/mempool`

The explorer is loopback-only in this checkpoint. It does not expose wallet
private keys and has no transaction/mining mutation endpoint.

The UI refreshes summary/latest blocks automatically and supports searching by
block height/hash or transaction ID.
