Set-Location $PSScriptRoot
Write-Host "Stopping Node 1..."
& .\.venv\Scripts\python.exe canonical_ops.py --datadir canonical-node1 stop --rpc-port 18443
Write-Host "Stopping Node 2..."
& .\.venv\Scripts\python.exe canonical_ops.py --datadir canonical-node2 stop --rpc-port 18453
