# Axven Core — Daily Use (Checkpoint 22)

Checkpoint 22 changes the user/operator layer only. Consensus identity and
canonical devnet history are unchanged.

## Windows: no PowerShell policy needed

Double-click or run:

- `setup.cmd` — create the Python environment/install Axven
- `start-node1.cmd` — start canonical Node 1
- `axven-console.cmd` — interactive Node 1 console
- `status-node1.cmd` — node/wallet overview
- `stop-node1.cmd` — graceful shutdown
- `start-node2.cmd` — start canonical Node 2
- `axven-console-node2.cmd` — interactive Node 2 console
- `status-node2.cmd` — Node 2 overview
- `sync-node2-from-node1.cmd` — synchronize Node 2 from Node 1
- `stop-node2.cmd` — graceful shutdown

## Interactive console

With Node 1 running, launch `axven-console.cmd`.

Commands:

```text
overview
status
addresses
balance
balance ed25519
balance ml-dsa-44
balance hybrid
utxos ed25519
mine 1 ed25519
send ed25519 <address> <amount> <fee>
sync 127.0.0.1 18454
stop
```

`exit` leaves the console but keeps the node running. `stop` gracefully stops
the node.

Amounts displayed by this checkpoint are raw Axven consensus units. A public
display denomination/decimal policy has not been introduced here.

## Canonical ports

Node 1:
- RPC: 18443
- P2P: 18444

Node 2:
- RPC: 18453
- P2P: 18454

RPC remains loopback-only in this checkpoint.


## Local Explorer

Node 1 browser:
`http://127.0.0.1:18445`

Node 2 browser:
`http://127.0.0.1:18455`

You can also double-click `open-explorer-node1.cmd` or
`open-explorer-node2.cmd`.
