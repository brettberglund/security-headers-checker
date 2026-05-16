# run_tests.ps1 - run unit/golden tests and all fuzz targets, then report results.
#
# Usage:
#   .\run_tests.ps1               # fuzz each target for 30 seconds (default)
#   .\run_tests.ps1 -FuzzSeconds 60
#   .\run_tests.ps1 -SkipFuzz    # unit/golden tests only
#
# Requirements for fuzz targets: nightly Rust + cargo-fuzz
#   rustup toolchain install nightly
#   cargo install cargo-fuzz
#
# Note: cargo-fuzz uses LLVM libFuzzer/SanCov, which does not link correctly on
# Windows (MSVC). Fuzz targets are skipped automatically on Windows; run them on
# Linux/macOS or in WSL / GitHub Actions.

param(
    [int]$FuzzSeconds = 30,
    [switch]$SkipFuzz
)

$script:failures = @()

function Invoke-Step {
    param([string]$Label, [string]$Exe, [string[]]$ExeArgs)
    Write-Host ""
    Write-Host "== $Label ==" -ForegroundColor Cyan
    & $Exe @ExeArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  FAILED: $Label" -ForegroundColor Red
        $script:failures += $Label
    } else {
        Write-Host "  PASSED: $Label" -ForegroundColor Green
    }
}

# Unit / Golden
Invoke-Step "Unit / golden tests" "cargo" @("test")

# Fuzz targets
$userIsWindows = $env:OS -eq "Windows_NT"

if (-not $SkipFuzz) {
    if ($userIsWindows) {
        Write-Host ""
        Write-Host "== Fuzz targets (SKIPPED on Windows) ==" -ForegroundColor Yellow
        Write-Host "  cargo-fuzz requires LLVM libFuzzer/SanCov, which does not link on Windows MSVC." -ForegroundColor Yellow
        Write-Host "  Run fuzz tests on Linux/macOS or in WSL / GitHub Actions." -ForegroundColor Yellow
    } else {
        $targets = @("fuzz_normalize", "fuzz_hsts", "fuzz_csp", "fuzz_x_frame_options")
        foreach ($target in $targets) {
            Invoke-Step "Fuzz: $target (${FuzzSeconds}s)" "cargo" @(
                "+nightly", "fuzz", "run", $target, "fuzz/corpus/$target",
                "--", "-max_total_time=$FuzzSeconds"
            )
        }
    }
}

# Summary
Write-Host ""
Write-Host ("-" * 60) -ForegroundColor DarkGray
if ($script:failures.Count -eq 0) {
    Write-Host "All checks passed." -ForegroundColor Green
    exit 0
} else {
    Write-Host "$($script:failures.Count) check(s) failed:" -ForegroundColor Red
    foreach ($f in $script:failures) {
        Write-Host "  - $f" -ForegroundColor Red
    }
    exit 1
}
