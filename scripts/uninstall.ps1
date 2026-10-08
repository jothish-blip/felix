# Felix CLI Windows Uninstallation Script
# Usage: powershell -ExecutionPolicy Bypass -File .\scripts\uninstall.ps1

$ErrorActionPreference = "Stop"

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host " FELIX :: Windows CLI Uninstallation" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

$installDir = Join-Path $env:LOCALAPPDATA "Felix\bin"
$targetExe = Join-Path $installDir "felix.exe"

# 1. Remove binary
if (Test-Path $targetExe) {
    Remove-Item -Path $targetExe -Force
    Write-Host "[+] Removed binary: $targetExe" -ForegroundColor Green
} else {
    Write-Host "[i] Binary not found at $targetExe" -ForegroundColor Gray
}

# Clean directory if empty
if (Test-Path $installDir) {
    $remaining = Get-ChildItem -Path $installDir
    if ($remaining.Count -eq 0) {
        Remove-Item -Path $installDir -Force -Recurse
        $parent = Split-Path $installDir -Parent
        if ((Test-Path $parent) -and ((Get-ChildItem -Path $parent).Count -eq 0)) {
            Remove-Item -Path $parent -Force -Recurse
        }
    }
}

# 2. Remove from User PATH
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath) {
    $paths = $userPath -split ';' | Where-Object { $_ -ne '' -and $_ -ne $installDir }
    $newPath = $paths -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "[+] Cleaned User PATH variable (removed $installDir)." -ForegroundColor Green
}

Write-Host ""
Write-Host "[+] Felix uninstalled successfully." -ForegroundColor Green
Write-Host "[i] Note: User config directory (~/.felix) was preserved." -ForegroundColor Gray
