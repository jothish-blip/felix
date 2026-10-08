<#
.SYNOPSIS
    Sterile Environment Validation Script

.DESCRIPTION
    Executes Felix release binary in a sanitized environment where Go, Git, and development
    toolchains are completely absent from the process PATH.
#>

$ErrorActionPreference = "Stop"

$RepoRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
$FelixBin = Join-Path $RepoRoot "dist\felix_windows_amd64.exe"

if (-not (Test-Path $FelixBin)) {
    Write-Error "Release binary not found at $FelixBin. Run build.ps1 first."
    exit 1
}

Write-Host "==========================================================="
Write-Host " Felix Clean Environment Isolation Test (No Go / No Git)"
Write-Host "==========================================================="

# Sanitize PATH: retain only system essentials
$SystemCleanPath = "C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\"
$env:Path = $SystemCleanPath

# 1. Assert Go is absent
$goCheck = Get-Command "go" -ErrorAction SilentlyContinue
if ($goCheck) {
    Write-Error "Go compiler is unexpectedly accessible in sterile environment"
    exit 1
}
Write-Host "[OK] Go compiler is absent from PATH."

# 2. Assert Git is absent
$gitCheck = Get-Command "git" -ErrorAction SilentlyContinue
if ($gitCheck) {
    Write-Error "Git is unexpectedly accessible in sterile environment"
    exit 1
}
Write-Host "[OK] Git toolchain is absent from PATH."

# 3. Verify felix version runs standalone
Write-Host "`n[*] Testing: felix version (zero dev dependencies)..."
& $FelixBin version
if ($LASTEXITCODE -ne 0) {
    Write-Error "felix version failed in clean environment"
    exit 1
}

# 4. Verify felix doctor runs standalone
Write-Host "`n[*] Testing: felix doctor (zero dev dependencies)..."
& $FelixBin doctor
if ($LASTEXITCODE -ne 0) {
    Write-Error "felix doctor failed in clean environment"
    exit 1
}

# 5. Verify felix scan runs standalone on live target
Write-Host "`n[*] Testing: felix scan https://example.com (zero dev dependencies)..."
$outReport = Join-Path $RepoRoot "clean_test_report.html"
if (Test-Path $outReport) { Remove-Item -Force $outReport }

& $FelixBin scan https://example.com --export $outReport
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1) {
    Write-Error "felix scan failed with unexpected code $LASTEXITCODE"
    exit 1
}

if (-not (Test-Path $outReport)) {
    Write-Error "Scan did not produce expected report: $outReport"
    exit 1
}

$sz = (Get-Item $outReport).Length
Write-Host "[OK] felix scan successfully executed without Go/Git and generated report ($sz bytes)"
Remove-Item -Force $outReport

Write-Host "`n==========================================================="
Write-Host " [OK] Sterile Environment Acceptance Test PASSED!"
Write-Host "==========================================================="
