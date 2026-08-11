# Checkpoint 20 — Canonical devnet-2 operations

Activation is already executed. This kit starts persistent canonical nodes.
It does not change consensus parameters or genesis.

## Important
Keep Checkpoint 17 (pre-activation proof) and Checkpoint 19 (post-activation
validated package) archived separately.

## Node 1 — canonical primary
PowerShell:
```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\canonical_node1_start.ps1
```

The first run creates `canonical-node1/wallet.json` and asks you to choose a
wallet passphrase. Then the node stays running.

Open a second PowerShell window in the same folder:
```powershell
.\canonical_node1_status.ps1
```

## First canonical mined block
When Node 1 status shows height 0 and the pinned devnet-2 identity:
```powershell
.\canonical_node1_mine1.ps1
```

The resulting block is persisted when the node stops cleanly.

## Node 2
In a third PowerShell window:
```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\canonical_node2_start.ps1
```

Then in another window:
```powershell
.\canonical_node2_sync_node1.ps1
```

Node 2 should catch up to Node 1.

## Stop cleanly
```powershell
.\canonical_stop_all.ps1
```

Do not kill the terminal while a node is persisting state unless necessary.

## Ports
Node 1:
- RPC 18443
- P2P 18444

Node 2:
- RPC 18453
- P2P 18454

These are local rehearsal ports. Internet-facing networking is a later
hardening/deployment milestone.
