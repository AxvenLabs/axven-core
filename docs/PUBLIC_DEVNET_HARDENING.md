# Public devnet hardening

The first public-network milestone should expose **P2P only**.

Keep these local-only:
- JSON-RPC;
- wallet operations;
- local explorer administration.

## Machine A

Run a node with P2P bound to an interface reachable from Machine B. Configure
the host firewall/router manually for the chosen P2P TCP port only.

Do not forward the RPC or explorer ports.

## Machine B

With Axven Core installed from the same canonical release:

```powershell
python tools\peer_probe.py <PUBLIC_IP_OR_DNS> <P2P_PORT>
python tools\public_peer_acceptance.py <PUBLIC_IP_OR_DNS> <P2P_PORT>
```

Expected acceptance:
- identity-bound handshake succeeds;
- `chain_id`, fingerprint and genesis are canonical;
- remote status returns height/tip/chainwork;
- an independent reconnect succeeds.

After that, perform an actual node-to-node synchronization using the normal
`sync-peer` path and compare height/tip on both machines.

## Do not automate router/firewall changes

This checkpoint intentionally does not open ports, change Windows Firewall,
configure UPnP, or expose RPC automatically. Public network exposure is an
operator-controlled deployment decision.
