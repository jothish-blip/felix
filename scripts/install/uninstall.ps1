<#
.SYNOPSIS
    Felix Windows Uninstaller

.DESCRIPTION
    Removes Felix binary from %LOCALAPPDATA%\Felix\bin, cleans the installation directory,
    and removes Felix from the User PATH environment variable. Preserves user scan results and config.
#>

$ErrorActionPreference = "Stop"

$InstallDir = Join-Path $env:LOCALAPPDATA "Felix\bin"
$TargetExe = Join-Path $InstallDir "felix.exe"

Write-Host "==========================================================="
Write-Host " FELIX :: Windows Automated Uninstaller"
Write-Host "==========================================================="

# 1. Remove binary
if (Test-Path $TargetExe) {
    Remove-Item -Path $TargetExe -Force
    Write-Host "[OK] Removed executable: $TargetExe"
} else {
    Write-Host "[-] Felix binary not found at: $TargetExe"
}

# 2. Clean directory if empty
if (Test-Path $InstallDir) {
    $remaining = Get-ChildItem -Path $InstallDir
    if ($remaining.Count -eq 0) {
        Remove-Item -Path $InstallDir -Force
        $parent = Split-Path $InstallDir -Parent
        if ((Get-ChildItem -Path $parent).Count -eq 0) {
            Remove-Item -Path $parent -Force
        }
        Write-Host "[OK] Removed installation directory: $InstallDir"
    }
}

# 3. Clean User PATH
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -and $UserPath -like "*$InstallDir*") {
    $CleanedPaths = ($UserPath -split ';' | Where-Object { $_ -ne '' -and $_ -ne $InstallDir }) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $CleanedPaths, "User")
    Write-Host "[OK] Removed $InstallDir from User PATH."
}

Write-Host ""
Write-Host "[i] Note: User configuration (~/.felix) and generated reports were preserved."
Write-Host "==========================================================="
Write-Host " [OK] Felix has been uninstalled successfully."
Write-Host "==========================================================="
