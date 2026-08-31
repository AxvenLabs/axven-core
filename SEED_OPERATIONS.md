# Public Seed Operations

Canonical endpoint: `seed.axven.org:18444`

## External read-only health check

From a validated Windows checkout:

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -File .\ensure_runtime.ps1
.\.venv\Scripts\python.exe tools\seed_health.py seed.axven.org 18444 --min-height 2
```

From a validated Linux/macOS checkout:

```bash
bash ensure_runtime.sh
.venv/bin/python tools/seed_health.py seed.axven.org 18444 --min-height 2
```

Do not replace these gates with ambient `python`, `pip`, or manual virtualenv
activation. The command validates canonical network identity, protocol version,
P2P reachability, remote status, minimum height, chainwork and tip hash shape.

## VPS operator checks

```bash
systemctl status axven-node --no-pager
ss -ltnp | grep 18444
cd /opt/axven-core
bash ensure_runtime.sh
.venv/bin/python canonical_ops.py status --rpc-port 18443
```

After changing or updating the VPS checkout, run `bash ensure_runtime.sh` before
restarting the service. A stale or missing provenance receipt is repaired only
through `validate_linux_macos.sh`; do not source `.venv/bin/activate` as a
substitute for validation.

Expected network boundary:

```text
0.0.0.0:18444    public P2P
127.0.0.1:18443  local RPC
127.0.0.1:18445  local explorer
```

Never publish `/etc/axven/seed.env` or the seed wallet backup.
