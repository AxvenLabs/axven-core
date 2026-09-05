# Checkpoint 30 — Outbound peering and seed sync

This checkpoint wires the existing P2P `connect()` / `sync_to_peer()` primitives
into the running Axven Core daemon.

Example home/devnet node:

```powershell
python axven_core.py --datadir home-node run `
  --rpc-host 127.0.0.1 --rpc-port 18443 `
  --p2p-host 127.0.0.1 --p2p-port 18444 `
  --explorer-host 127.0.0.1 --explorer-port 18445 `
  --peer seed.axven.org:18444 `
  --sync-interval 5
```

Behavior:
- performs an initial locator-based catch-up from each configured outbound peer;
- retries peer synchronization periodically;
- peer failures are recorded and do not crash the daemon;
- locally mined blocks are proactively propagated to outbound peers;
- locally created transactions are proactively propagated to outbound peers.

This changes node networking behavior only. It does not change consensus,
genesis, configuration fingerprint, transaction validity, or block validity.
