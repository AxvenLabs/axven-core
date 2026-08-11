$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv")) {
    py -3 -m venv .venv
    & .\.venv\Scripts\python.exe -m pip install -e .
}

$DataDir = Join-Path $PSScriptRoot "canonical-node2"
if (-not (Test-Path (Join-Path $DataDir "wallet.json"))) {
    Write-Host "Creating canonical Node 2 wallet..." -ForegroundColor Cyan
    & .\.venv\Scripts\python.exe axven_core.py --datadir $DataDir create-wallet
}

Write-Host "Starting canonical Node 2" -ForegroundColor Green
Write-Host "RPC: 127.0.0.1:18453 | P2P: 127.0.0.1:18454 | Explorer: http://127.0.0.1:18455"
& .\.venv\Scripts\python.exe axven_core.py --datadir $DataDir run --rpc-port 18453 --p2p-port 18454 --explorer-port 18455
