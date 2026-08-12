# Axven Public Devnet Acceptance Record

Checkpoint 31 records the first real public two-machine Axven devnet operation.

## Canonical network identity

- Network: `axven-devnet-2`
- Config fingerprint: `ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae`
- Genesis: `a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3`
- P2P protocol version: `1`
- Public seed: `seed.axven.org:18444`

## Public seed deployment

The canonical public seed node runs on an Ubuntu 24.04 VPS.

Network boundary:
- P2P: `0.0.0.0:18444`
- RPC: `127.0.0.1:18443`
- Explorer: `127.0.0.1:18445`

Only TCP port `18444` is publicly allowed by the VPS firewall.
The node is managed by `systemd` as `axven-node.service` and is enabled at boot.

## Public-network acceptance

- DNS resolution for `seed.axven.org` succeeded.
- TCP connection to `seed.axven.org:18444` succeeded.
- Axven identity-bound P2P handshake succeeded.
- Remote status request succeeded.
- Independent reconnect succeeded.
- Windows node established outbound synchronization to the seed.

## Cross-machine block propagation

Block #1 was mined on the Windows node and propagated over public P2P to the VPS seed.

- Height: `1`
- Block hash: `006773650210f2c0fbe1eb97526e294bc7343a6aec1a5617889803cf489c04eb`
- Resulting chainwork: `512`

Block #2 was mined on the VPS seed and pulled by the Windows node through periodic outbound synchronization.

- Height: `2`
- Block hash: `002fdc15afd2f247ae3239b205486d0f482107c45b448528edcd52730f888edd`
- Resulting chainwork: `768`

Both machines converged on exactly the same height, chainwork and tip hash.

## Restart persistence acceptance

The VPS was rebooted after reaching height `2`.

After reboot:
- `axven-node.service` started automatically.
- wallet loaded successfully.
- chain replay restored height `2`.
- chainwork restored to `768`.
- tip hash remained exactly `002fdc15afd2f247ae3239b205486d0f482107c45b448528edcd52730f888edd`.

This proves public seed persistence across a full machine restart.

## Security boundary

This record is for the canonical devnet only. It is not a mainnet launch record.
RPC and explorer remain loopback-only. No wallet passphrases, private keys,
wallet backups, or seed material are included in this record.
