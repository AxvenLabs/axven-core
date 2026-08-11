# Checkpoint 29 — Public P2P boundary

Goal: expose only the Axven P2P listener to a remote machine.

The daemon now has separate bind addresses:
- `--rpc-host`
- `--p2p-host`
- `--explorer-host`

Recommended public-devnet launch:

```text
RPC       127.0.0.1:18443
P2P       0.0.0.0:18444
Explorer  127.0.0.1:18445
```

Use `start-public-p2p-node.cmd` on Windows.

Only TCP port `18444` should be allowed/forwarded through the host firewall/router.
Do not forward 18443 or 18445.

Remote acceptance from another Internet connection:

```powershell
python tools\peer_probe.py <PUBLIC_IP_OR_DNS> 18444
python tools\public_peer_acceptance.py <PUBLIC_IP_OR_DNS> 18444
```

This checkpoint does not automate Windows Firewall, router NAT, UPnP, or port
forwarding. Those remain explicit operator decisions.
