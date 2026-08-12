# Public Seed Operations

Canonical endpoint: `seed.axven.org:18444`

## External read-only health check

```powershell
python tools\seed_health.py seed.axven.org 18444 --min-height 2
```

The command validates canonical network identity, protocol version, P2P
reachability, remote status, minimum height, chainwork and tip hash shape.

## VPS operator checks

```bash
systemctl status axven-node --no-pager
ss -ltnp | grep 18444
cd /opt/axven-core
source .venv/bin/activate
python canonical_ops.py status --rpc-port 18443
```

Expected network boundary:

```text
0.0.0.0:18444    public P2P
127.0.0.1:18443  local RPC
127.0.0.1:18445  local explorer
```

Never publish `/etc/axven/seed.env` or the seed wallet backup.
