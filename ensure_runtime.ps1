$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$Python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$PythonDigest = Join-Path $PSScriptRoot ".venv\.axven-python.sha256"

function Test-AxvenInterpreterDigest {
    if (-not (Test-Path $Python -PathType Leaf)) { return $false }
    if (-not (Test-Path $PythonDigest -PathType Leaf)) { return $false }
    $Expected = (Get-Content -LiteralPath $PythonDigest -Raw).Trim()
    if ($Expected -notmatch "^[0-9a-f]{64}$") { return $false }
    $Actual = (Get-FileHash -LiteralPath $Python -Algorithm SHA256).Hash.ToLowerInvariant()
    return $Actual -eq $Expected
}

function Test-AxvenValidatedRuntime {
    if (-not (Test-Path $Python -PathType Leaf)) {
        return $false
    }
    if (-not (Test-AxvenInterpreterDigest)) {
        return $false
    }

    & $Python runtime_provenance.py check *> $null
    if ($LASTEXITCODE -ne 0) {
        return $false
    }

    & $Python doctor.py *> $null
    if ($LASTEXITCODE -ne 0) {
        return $false
    }

    return $true
}

if ((Test-Path $Python -PathType Leaf) -and -not (Test-AxvenInterpreterDigest)) {
    throw "Axven runtime interpreter attestation is missing or mismatched; remove .venv and rerun validate_windows.ps1"
}

if (-not (Test-AxvenValidatedRuntime)) {
    Write-Host "Axven runtime is missing, stale, or unvalidated; running hardened validation..." -ForegroundColor Yellow
    & (Join-Path $PSScriptRoot "validate_windows.ps1")
}

if (-not (Test-AxvenValidatedRuntime)) {
    throw "Axven runtime provenance validation failed"
}

Write-Host "Axven runtime provenance: GREEN" -ForegroundColor Green
