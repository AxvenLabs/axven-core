$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$RequiredPython = "3.13.15"

# SEC-219: the ambient interpreter is not trusted to import site/user startup
# hooks while selecting the exact bootstrap runtime.
py -3.13 -I -S -c "import platform,sys; raise SystemExit(0 if platform.python_version() == '$RequiredPython' else 2)"
if ($LASTEXITCODE -ne 0) { throw "Python $RequiredPython is required" }

# Never reuse a pre-existing virtualenv during hardened validation. A stale
# environment can contain sitecustomize/.pth startup code that executes before
# Axven's provenance checks. Reparse points are removed as links; ordinary
# generated virtualenv directories are rebuilt from scratch.
$VenvPath = Join-Path $PSScriptRoot ".venv"
$ExistingVenv = Get-Item -LiteralPath $VenvPath -Force -ErrorAction SilentlyContinue
if ($null -ne $ExistingVenv) {
    if (($ExistingVenv.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Remove-Item -LiteralPath $VenvPath -Force
    }
    elseif ($ExistingVenv.PSIsContainer) {
        Remove-Item -LiteralPath $VenvPath -Recurse -Force
    }
    else {
        throw ".venv exists but is not a removable virtualenv directory"
    }
}

py -3.13 -I -S -m venv .venv
if ($LASTEXITCODE -ne 0) { throw "virtualenv creation failed" }

$Python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
& $Python -I -S -c "import platform,sys; raise SystemExit(0 if platform.python_version() == '$RequiredPython' else 2)"
if ($LASTEXITCODE -ne 0) {
    throw "fresh .venv is not Python $RequiredPython"
}

Write-Host "`n=== HASH-LOCKED DEPENDENCIES ===" -ForegroundColor Cyan
& $Python -m pip install --no-deps --only-binary=:all: --require-hashes -r requirements-ci-toolchain.lock
if ($LASTEXITCODE -ne 0) { throw "hash-locked toolchain install failed" }
& $Python -m pip install --no-deps --only-binary=:all: --require-hashes -r requirements-ci-runtime-windows.lock
if ($LASTEXITCODE -ne 0) { throw "hash-locked runtime install failed" }
& $Python -m pip install --no-build-isolation --no-deps -e ".[legacy-mldsa-recovery]"
if ($LASTEXITCODE -ne 0) { throw "Axven editable install failed" }
& $Python -m pip check
if ($LASTEXITCODE -ne 0) { throw "pip check failed" }

Write-Host "`n=== AXVEN DOCTOR ===" -ForegroundColor Cyan
& $Python doctor.py
if ($LASTEXITCODE -ne 0) { throw "axven-doctor failed" }

Write-Host "`n=== FULL VALIDATION ===" -ForegroundColor Cyan
& $Python run_full_validation.py
if ($LASTEXITCODE -ne 0) { throw "Axven validation failed" }

Write-Host "`n=== SEC-076+ SECURITY TAIL ===" -ForegroundColor Cyan
& $Python security_tail_runner.py
if ($LASTEXITCODE -ne 0) { throw "Axven security tail failed" }

Write-Host "`n=== RUNTIME PROVENANCE RECEIPT ===" -ForegroundColor Cyan
& $Python runtime_provenance.py stamp
if ($LASTEXITCODE -ne 0) { throw "runtime provenance receipt failed" }

Write-Host "`nALL AXVEN CHECKS GREEN" -ForegroundColor Green
