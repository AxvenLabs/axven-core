$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
& (Join-Path $PSScriptRoot "ensure_runtime.ps1")
& .\.venv\Scripts\python.exe canonical_ops.py --datadir canonical-node1 mine 1 --rpc-port 18443 --scheme ed25519
