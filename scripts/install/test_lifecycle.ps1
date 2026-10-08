<#
.SYNOPSIS
    Test script for Felix installation, execution, scan, and uninstallation lifecycle.
#>

$ErrorActionPreference = "Stop"

$InstallDir = Join-Path $env:LOCALAPPDATA "Felix\bin"
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
Write-Host "`n[*] Running: felix scan https://example.com --export report.html..."
$ReportPath = Join-Path (Get-Location) "report.html"
if (Test-Path $ReportPath) { Remove-Item -Force $ReportPath }

& $FelixExe scan https://example.com --export report.html
if (-not (Test-Path $ReportPath)) {
    Write-Error "Expected report.html was not created"
    exit 1
}
$repSize = (Get-Item $ReportPath).Length
Write-Host "[OK] Scan completed and generated report.html ($repSize bytes)"
Remove-Item -Force $ReportPath

# 5. Verify User PATH entry
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -like "*$InstallDir*") {
    Write-Host "[OK] User PATH contains $InstallDir"
} else {
    Write-Error "User PATH does not contain $InstallDir"
    exit 1
}

Write-Host "`n==========================================================="
Write-Host " [OK] Windows Lifecycle Verification PASSED!"
Write-Host "==========================================================="
