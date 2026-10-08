# Felix CLI Windows Installation Script
# Usage: powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1

$ErrorActionPreference = "Stop"

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host " FELIX :: Windows CLI Installation" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

# 1. Determine local app data target directory
$installDir = Join-Path $env:LOCALAPPDATA "Felix\bin"
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

# 2. Locate or build felix.exe
$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceExe = Join-Path $repoRoot "bin\felix.exe"

if (-not (Test-Path $sourceExe)) {
    Write-Host "[*] Building felix.exe from source..." -ForegroundColor Yellow
    Push-Location $repoRoot
    try {
        $goCmd = Get-Command go -ErrorAction SilentlyContinue
        if (-not $goCmd) {
            $env:PATH = "C:\Program Files\Go\bin;" + $env:PATH
        }
        go build -o bin\felix.exe .\cmd\felix
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path $sourceExe)) {
    Write-Error "[-] Could not locate or build bin\felix.exe"
    exit 2
}

# 3. Copy binary
$targetExe = Join-Path $installDir "felix.exe"
Copy-Item -Path $sourceExe -Destination $targetExe -Force
Write-Host "[+] Installed felix.exe to: $targetExe" -ForegroundColor Green

# 4. Add to User PATH if not already present
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$paths = $userPath -split ';' | Where-Object { $_ -ne '' }
if ($paths -notcontains $installDir) {
    $newPath = ($paths + $installDir) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "[+] Registered $installDir in User PATH environment variable." -ForegroundColor Green
} else {
    Write-Host "[i] $installDir is already in User PATH." -ForegroundColor Gray
}

# 5. Verify installed binary
$verOutput = & $targetExe version
Write-Host ""
Write-Host "[+] Felix installation verified successfully:" -ForegroundColor Green
Write-Host $verOutput -ForegroundColor Gray
Write-Host ""
Write-Host "You can now open any new terminal window and run: felix --help" -ForegroundColor Cyan
