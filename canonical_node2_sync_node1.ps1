Set-Location $PSScriptRoot
& .\.venv\Scripts\python.exe canonical_ops.py sync 127.0.0.1 18444 --rpc-port 18453
