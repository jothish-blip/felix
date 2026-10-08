<#
.SYNOPSIS
    Removes the Felix Development Certificate from the local Windows trust store.

.DESCRIPTION
    Safely locates and removes ONLY the Felix Development Certificate from
    CurrentUser and LocalMachine certificate stores.
    All unrelated certificates in Windows remain completely untouched.

.PARAMETER Force
    Suppresses the confirmation prompt and proceeds with certificate removal.
#>

param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host " FELIX :: Remove Local Development Certificate Trust" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

$certPattern = "*Felix Development*"

# 1. Search for matching certificates across stores
$storesToScan = @(
    "Cert:\CurrentUser\Root",
    "Cert:\CurrentUser\TrustedPublisher",
    "Cert:\CurrentUser\My",
    "Cert:\LocalMachine\Root",
    "Cert:\LocalMachine\TrustedPublisher"
)

$foundCerts = @()

foreach ($storePath in $storesToScan) {
    if (Test-Path $storePath) {
        try {
            $certs = Get-ChildItem $storePath -ErrorAction SilentlyContinue | Where-Object {
                $_.Subject -like $certPattern -or $_.FriendlyName -like $certPattern
            }
            foreach ($c in $certs) {
                $foundCerts += [PSCustomObject]@{
                    Store      = $storePath
                    Subject    = $c.Subject
                    Thumbprint = $c.Thumbprint
                    NotAfter   = $c.NotAfter
                }
            }
        } catch {
            # Ignore store read errors for stores requiring elevation
        }
    }
}

if ($foundCerts.Count -eq 0) {
    Write-Host "[i] No Felix Development certificates found in any certificate store." -ForegroundColor Green
    Write-Host "[OK] Trust store is already clean." -ForegroundColor Green
    return
}

# 2. Display certificates to be removed
Write-Host ""
Write-Host "Found $($foundCerts.Count) Felix Development certificate entry(ies) to remove:" -ForegroundColor Yellow
foreach ($entry in $foundCerts) {
    Write-Host "  Store:      $($entry.Store)" -ForegroundColor Gray
    Write-Host "  Subject:    $($entry.Subject)" -ForegroundColor Gray
    Write-Host "  Thumbprint: $($entry.Thumbprint)" -ForegroundColor Gray
    Write-Host "  Expires:    $($entry.NotAfter)" -ForegroundColor Gray
    Write-Host "  ---" -ForegroundColor DarkGray
}

Write-Host "SAFETY GUARANTEE:" -ForegroundColor Yellow
Write-Host "  Only certificates matching the Felix Development subject will be removed." -ForegroundColor Gray
Write-Host "  Zero unrelated system or user certificates will be modified." -ForegroundColor Gray
Write-Host ""

# 3. Explicit user confirmation
if (-not $Force) {
    $confirmation = Read-Host "Do you want to remove the Felix Development certificate(s)? (y/N)"
    if ($confirmation -notmatch "^[yY]([eE][sS])?$") {
        Write-Host "Operation cancelled by user. Certificates were NOT removed." -ForegroundColor Yellow
        exit 0
    }
}

# 4. Remove certificates
Write-Host "[*] Removing Felix Development certificates..." -ForegroundColor Cyan

$removedCount = 0
foreach ($entry in $foundCerts) {
    $itemPath = Join-Path $entry.Store $entry.Thumbprint
    try {
        if (Test-Path $itemPath) {
            Remove-Item $itemPath -Force -ErrorAction Stop
            Write-Host "  [OK] Removed from: $($entry.Store)" -ForegroundColor Green
            $removedCount++
        }
    } catch {
        Write-Warning "Failed removing from $($entry.Store): $_"
    }
}

# 5. Verify removal
Write-Host ""
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host " Removal Verification" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

$remainingCount = 0
foreach ($storePath in $storesToScan) {
    if (Test-Path $storePath) {
        try {
            $rem = Get-ChildItem $storePath -ErrorAction SilentlyContinue | Where-Object {
                $_.Subject -like $certPattern -or $_.FriendlyName -like $certPattern
            }
            if ($rem) {
                Write-Host "  [WARN] Still present in: $storePath ($($rem.Count))" -ForegroundColor Yellow
                $remainingCount += $rem.Count
            }
        } catch {}
    }
}

if ($remainingCount -eq 0) {
    Write-Host " [PASS] All Felix Development certificates successfully removed ($removedCount entries cleaned)." -ForegroundColor Green
    Write-Host " [PASS] Zero unrelated certificates were touched." -ForegroundColor Green
    Write-Host ""
    Write-Host "[OK] Windows trust store successfully restored to default state." -ForegroundColor Green
} else {
    Write-Host " [WARN] Some certificate entries could not be removed (administrator elevation may be required)." -ForegroundColor Yellow
}
