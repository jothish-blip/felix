<#
.SYNOPSIS
    Felix Multi-Platform Release Build Script

.DESCRIPTION
    Cross-compiles Felix for all supported target platforms (Windows amd64, Linux amd64/arm64, macOS amd64/arm64),
    injects release metadata via ldflags, packages distribution archives, and computes SHA-256 checksums.
#>

param(
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"

# Locate Go compiler
$GoCmd = "go"
if (-not (Get-Command "go" -ErrorAction SilentlyContinue)) {
    if (Test-Path "C:\Program Files\Go\bin\go.exe") {
        $GoCmd = "C:\Program Files\Go\bin\go.exe"
    } else {
        Write-Error "Go toolchain not found."
        exit 1
    }
}

$RepoRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
Set-Location $RepoRoot

$DistDir = Join-Path $RepoRoot "dist"
if (Test-Path $DistDir) {
    Remove-Item -Recurse -Force $DistDir
}
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

# Resolve Git commit and build timestamp
$Commit = "dev"
try {
    $Commit = (git rev-parse --short HEAD).Trim()
} catch {}

$BuildTime = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
$LDFlags = "-s -w -X main.Version=$Version -X main.GitCommit=$Commit -X main.BuildTime=$BuildTime -X main.Release=Production"

Write-Host "==========================================================="
Write-Host " Building Felix Cross-Platform Release v$Version ($Commit)"
Write-Host "==========================================================="

$Targets = @(
    @{ OS = "windows"; Arch = "amd64"; Output = "felix_windows_amd64.exe"; BinName = "felix.exe" },
    @{ OS = "linux";   Arch = "amd64"; Output = "felix_linux_amd64";       BinName = "felix" },
    @{ OS = "linux";   Arch = "arm64"; Output = "felix_linux_arm64";       BinName = "felix" },
    @{ OS = "darwin";  Arch = "amd64"; Output = "felix_darwin_amd64";      BinName = "felix" },
    @{ OS = "darwin";  Arch = "arm64"; Output = "felix_darwin_arm64";      BinName = "felix" }
)

foreach ($t in $Targets) {
    $targetOS = $t.OS
    $targetArch = $t.Arch
    $targetOut = $t.Output
    $outPath = Join-Path $DistDir $targetOut
    Write-Host "[*] Compiling $targetOS/$targetArch -> $targetOut..."

    $env:GOOS = $targetOS
    $env:GOARCH = $targetArch
    $env:CGO_ENABLED = "0"

    & $GoCmd build -trimpath -ldflags $LDFlags -o $outPath ./cmd/felix
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to build $targetOS/$targetArch"
        exit 1
    }

    if (-not (Test-Path $outPath)) {
        Write-Error "Output artifact not found: $outPath"
        exit 1
    }
    $fileInfo = Get-Item $outPath
    $sizeMB = [math]::Round($fileInfo.Length / 1048576, 2)
    Write-Host "    [OK] Built successfully ($sizeMB MB)"
}

Remove-Item env:GOOS -ErrorAction SilentlyContinue
Remove-Item env:GOARCH -ErrorAction SilentlyContinue
Remove-Item env:CGO_ENABLED -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[*] Packaging distribution archives..."

$DocsToInclude = @("README.md", "USAGE.md", "SECURITY.md")

foreach ($t in $Targets) {
    $targetOS = $t.OS
    $targetArch = $t.Arch
    $rawBin = Join-Path $DistDir $t.Output
    $stageDir = Join-Path $DistDir "stage_${targetOS}_${targetArch}"
    New-Item -ItemType Directory -Force -Path $stageDir | Out-Null

    Copy-Item $rawBin (Join-Path $stageDir $t.BinName)

    foreach ($doc in $DocsToInclude) {
        $docPath = Join-Path $RepoRoot $doc
        if (Test-Path $docPath) {
            Copy-Item $docPath (Join-Path $stageDir $doc)
        }
    }

    if ($targetOS -eq "windows") {
        $zipName = "felix_${Version}_windows_${targetArch}.zip"
        $zipPath = Join-Path $DistDir $zipName
        if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
        Compress-Archive -Path "$stageDir\*" -DestinationPath $zipPath
        Write-Host "    [OK] Created archive: $zipName"
    } else {
        $tarName = "felix_${Version}_${targetOS}_${targetArch}.tar.gz"
        $tarPath = Join-Path $DistDir $tarName
        tar -czf $tarPath -C $stageDir .
        Write-Host "    [OK] Created archive: $tarName"
    }

    Remove-Item -Recurse -Force $stageDir
}

Write-Host ""
Write-Host "[*] Generating SHA256SUMS..."
$SumsFile = Join-Path $DistDir "SHA256SUMS"
$hashLines = @()

Get-ChildItem -Path $DistDir -File | Where-Object { $_.Name -ne "SHA256SUMS" } | ForEach-Object {
    $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash.ToLower()
    $line = "$hash  $($_.Name)"
    $hashLines += $line
}

$hashLines | Out-File -FilePath $SumsFile -Encoding ascii
Write-Host "[OK] SHA256SUMS generated for $($hashLines.Count) artifacts."
Write-Host ""
Write-Host "==========================================================="
Write-Host " Release Build Complete: artifacts ready in dist/"
Write-Host "==========================================================="
Get-ChildItem -Path $DistDir | Select-Object Name, Length | Format-Table -AutoSize
