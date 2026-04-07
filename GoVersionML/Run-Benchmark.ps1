<#
.SYNOPSIS
Runs the Go benchmark suite to analyze performance (RAM, CPU, execution time).

.DESCRIPTION
This script automatically runs the end-to-end benchmark 5 times and displays statistics.
If you provide the -Compare switch, it will compare the current run to a previous 'baseline.txt'
so you can see if your changes made the code faster or slower.

.EXAMPLE
.\Run-Benchmark.ps1
Runs 5 benchmark passes and outputs the current performance stats.

.EXAMPLE
.\Run-Benchmark.ps1 -SaveBaseline
Runs the benchmark exactly 5 times and saves it as 'baseline.txt' to compare later.

.EXAMPLE
.\Run-Benchmark.ps1 -Compare
Runs the benchmark exactly 5 times, then compares it against 'baseline.txt' showing delta metrics.
#>

param(
    [switch]$SaveBaseline,
    [switch]$Compare,
    [switch]$Profile
)

$OutputFile = "current_benchmark.txt"
if ($SaveBaseline) {
    $OutputFile = "baseline.txt"
}

$ProfileFlags = ""
if ($Profile) {
    $ProfileFlags = "-cpuprofile=cpu.prof -memprofile=mem.prof"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Starting Go E2E Benchmarks (Running 5 passes for accuracy)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Please wait... This might take a few minutes for large files.`n" -ForegroundColor Yellow

$Command = "go test ./main -bench=BenchmarkEndToEnd -benchmem -count=6 -timeout=30m $ProfileFlags"
Invoke-Expression "$Command | Out-File -FilePath $OutputFile -Encoding utf8"

if ($SaveBaseline) {
    Write-Host "`n[SUCCESS] Baseline saved to 'baseline.txt'." -ForegroundColor Green
    Write-Host "You can now make code changes and run '.\Run-Benchmark.ps1 -Compare' to test efficiency differences." -ForegroundColor Green
} else {
    if ($Compare) {
        if (Test-Path "baseline.txt") {
            Write-Host "`nComparing against baseline:" -ForegroundColor Cyan
            go run golang.org/x/perf/cmd/benchstat@latest baseline.txt $OutputFile
        } else {
            Write-Host "`n[ERROR] No baseline.txt found! Run '.\Run-Benchmark.ps1 -SaveBaseline' first." -ForegroundColor Red
        }
    } else {
        Write-Host "`nCurrent Benchmark Results:" -ForegroundColor Cyan
        go run golang.org/x/perf/cmd/benchstat@latest $OutputFile
    }
}

if ($Profile) {
    Write-Host "`n[SUCCESS] Profiles saved. To investigate memory or CPU allocation, use:" -ForegroundColor Green
    Write-Host "  go tool pprof -http=:8080 cpu.prof"
    Write-Host "  go tool pprof -http=:8080 mem.prof"
}
