$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$RequiredPython = "3.13.15"

# Fail closed on the exact validated runtime before creating a virtualenv or
# performing any package installation. The launcher may select a later 3.13
# patch over time, so verify the concrete interpreter rather than trusting
# the selector alone.
py -3.13 -c "import platform,sys; raise SystemExit(0 if platform.python_version() == '$RequiredPython' else 2)"
if ($LASTEXITCODE -ne 0) { throw "Python $RequiredPython is required" }

$CreatedVenv = $false
if (-not (Test-Path ".venv")) {
    py -3.13 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "virtualenv creation failed" }
    $CreatedVenv = $true
}

$Python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$PythonDigest = Join-Path $PSScriptRoot ".venv\.axven-python.sha256"
$Verifier = Join-Path $PSScriptRoot "runtime_provenance.py"
$VerifierDigest = Join-Path $PSScriptRoot ".venv\.axven-runtime-provenance.sha256"
if (-not $CreatedVenv) {
    if (-not (Test-Path $Python -PathType Leaf) -or -not (Test-Path $PythonDigest -PathType Leaf)) {
        throw "existing .venv lacks interpreter attestation; remove it and rerun"
    }
    $ExpectedDigest = (Get-Content -LiteralPath $PythonDigest -Raw).Trim()
    if ($ExpectedDigest -notmatch "^[0-9a-f]{64}$") {
        throw "existing .venv interpreter attestation is invalid; remove it and rerun"
    }
    $ActualDigest = (Get-FileHash -LiteralPath $Python -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualDigest -ne $ExpectedDigest) {
        throw "existing .venv interpreter attestation mismatch; remove it and rerun"
    }
    if (-not (Test-Path $Verifier -PathType Leaf) -or -not (Test-Path $VerifierDigest -PathType Leaf)) {
        throw "existing .venv lacks provenance verifier attestation; remove it and rerun"
    }
    $ExpectedVerifierDigest = (Get-Content -LiteralPath $VerifierDigest -Raw).Trim()
    if ($ExpectedVerifierDigest -notmatch "^[0-9a-f]{64}$") {
        throw "existing .venv provenance verifier attestation is invalid; remove it and rerun"
    }
    $ActualVerifierDigest = (Get-FileHash -LiteralPath $Verifier -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualVerifierDigest -ne $ExpectedVerifierDigest) {
        throw "existing .venv provenance verifier attestation mismatch; remove it and rerun"
    }
}
& $Python -c "import platform,sys; raise SystemExit(0 if platform.python_version() == '$RequiredPython' else 2)"
if ($LASTEXITCODE -ne 0) {
    throw "existing .venv is not Python $RequiredPython; remove it and rerun"
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
