$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

& (Join-Path $PSScriptRoot "ensure_runtime.ps1")

$DataDir = Join-Path $PSScriptRoot "canonical-node1"
if (-not (Test-Path (Join-Path $DataDir "wallet.json"))) {
    Write-Host "Creating canonical Node 1 wallet..." -ForegroundColor Cyan
    & .\.venv\Scripts\python.exe axven_core.py --datadir $DataDir create-wallet
}

Write-Host "Starting canonical Node 1" -ForegroundColor Green
Write-Host "RPC: 127.0.0.1:18443 | P2P: 127.0.0.1:18444 | Explorer: http://127.0.0.1:18445"
& .\.venv\Scripts\python.exe axven_core.py --datadir $DataDir run --rpc-port 18443 --p2p-port 18444 --explorer-port 18445
