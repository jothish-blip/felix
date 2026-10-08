<#
.SYNOPSIS
    Felix Benchmark & Certification Suite Runner

.DESCRIPTION
    Executes Felix deterministic and live benchmarks, evaluates hard security assertions,
    verifies false-positive suppression, and produces certification reports.

.PARAMETER SyntheticOnly
    Run only the deterministic synthetic certification harness.

.PARAMETER LiveOnly
    Run only authorized live targets.

.PARAMETER Baseline
    Save the results as the official baseline (benchmarks/results/baseline.json).

.PARAMETER Compare
    Compare previous.json with current.json.

.EXAMPLE
    .\benchmarks\scripts\run-benchmark.ps1
    .\benchmarks\scripts\run-benchmark.ps1 -SyntheticOnly
    .\benchmarks\scripts\run-benchmark.ps1 -Baseline
    .\benchmarks\scripts\run-benchmark.ps1 -Compare benchmarks/results/baseline.json benchmarks/results/latest.json
#>

param(
    [switch]$SyntheticOnly,
    [switch]$LiveOnly,
    [switch]$Baseline,
    [string[]]$Compare,
    [string]$Out = ""
)

$ErrorActionPreference = "Stop"

# Locate Go executable
$GoPath = "go"
if (-not (Get-Command "go" -ErrorAction SilentlyContinue)) {
    if (Test-Path "C:\Program Files\Go\bin\go.exe") {
        $GoPath = "C:\Program Files\Go\bin\go.exe"
    } else {
        Write-Error "Go toolchain not found in PATH or standard installation path."
        exit 1
    }
}

$RepoRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
Set-Location $RepoRoot

$ArgsList = @("run", "./benchmarks")

if ($Compare -and $Compare.Count -ge 2) {
    $ArgsList += @("--compare", $Compare[0], $Compare[1])
} else {
    if ($SyntheticOnly) {
        $ArgsList += "--synthetic-only"
    }
    if ($LiveOnly) {
        $ArgsList += "--live-only"
    }
    if ($Baseline) {
        $ArgsList += "--baseline"
    }
    if ($Out -ne "") {
        $ArgsList += @("--out", $Out)
    }
}

& $GoPath $ArgsList
exit $LASTEXITCODE
