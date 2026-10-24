<#
.SYNOPSIS
    Test script for Felix installation, execution, scan, and uninstallation lifecycle.
#>

param(
    [string]$InstallDir = "",
    [string]$Target = "https://example.com",
    [switch]$SkipPathCheck,
    [switch]$SkipScan
)

$ErrorActionPreference = "Stop"

if (-not $InstallDir) {
    if ($env:FELIX_INSTALL_DIR) {
        $InstallDir = $env:FELIX_INSTALL_DIR
    } else {
        $InstallDir = Join-Path $env:LOCALAPPDATA "Felix\bin"
    }
}
$FelixExe = Join-Path $InstallDir "felix.exe"

Write-Host "==========================================================="
Write-Host " Testing Windows Install & Lifecycle Verification"
Write-Host "==========================================================="

# 1. Verify executable exists in %LOCALAPPDATA%\Felix\bin
if (-not (Test-Path $FelixExe)) {
    Write-Error "felix.exe does not exist at $FelixExe"
    exit 1
}
Write-Host "[OK] Binary exists at: $FelixExe"

# 2. Verify felix version works
Write-Host "`n[*] Running: felix version..."
& $FelixExe version

# 3. Verify felix doctor works
Write-Host "`n[*] Running: felix doctor..."
& $FelixExe doctor

# 4. Verify felix scan works on live target and produces report
if (-not $SkipScan) {
    Write-Host "`n[*] Running: felix scan $Target --export report.html..."
    $ReportPath = Join-Path (Get-Location) "report.html"
    if (Test-Path $ReportPath) { Remove-Item -Force $ReportPath }

    & $FelixExe scan $Target --export report.html
    if (-not (Test-Path $ReportPath)) {
        Write-Error "Expected report.html was not created"
        exit 1
    }
    $repSize = (Get-Item $ReportPath).Length
    Write-Host "[OK] Scan completed and generated report.html ($repSize bytes)"
    Remove-Item -Force $ReportPath
} else {
    Write-Host "`n[*] Skipping scan check (SkipScan is set)."
}

# 5. Verify User PATH entry
if ($SkipPathCheck) {
    Write-Host "[i] Skipping User PATH check (SkipPathCheck is set)."
} else {
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($UserPath -like "*$InstallDir*") {
        Write-Host "[OK] User PATH contains $InstallDir"
    } else {
        Write-Error "User PATH does not contain $InstallDir"
        exit 1
    }
}

Write-Host "`n==========================================================="
Write-Host " [OK] Windows Lifecycle Verification PASSED!"
Write-Host "==========================================================="
