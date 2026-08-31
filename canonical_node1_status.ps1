$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
& (Join-Path $PSScriptRoot "ensure_runtime.ps1")
& .\.venv\Scripts\python.exe canonical_ops.py --datadir canonical-node1 status --rpc-port 18443
