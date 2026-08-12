# Run unit tests with coverage validation
# Checks: 10% baseline coverage, 80% incremental coverage for changed code
# PowerShell version for Windows

$ErrorActionPreference = "Stop"

Write-Host "🧪 Running unit tests with coverage validation..." -ForegroundColor Cyan
Write-Host ""

# Configuration
$BASELINE_COVERAGE = 10    # Minimum overall coverage (%)
$INCREMENTAL_COVERAGE = 80 # Minimum coverage for changed code (%)

# Check if Go is installed
try {
    $null = Get-Command go -ErrorAction Stop
} catch {
    Write-Host "❌ Go is not installed" -ForegroundColor Red
    exit 1
}

# Check if go.mod exists
if (-not (Test-Path "go.mod")) {
    Write-Host "❌ go.mod not found. Is this a Go module?" -ForegroundColor Red
    exit 1
}

# Run tests with coverage
# go test writes warnings to stderr for packages with no test files; use Continue to avoid NativeCommandError
$ErrorActionPreference = "Continue"
Write-Host "Running tests..." -ForegroundColor Yellow
$testOutput = go test '-coverprofile=coverage.out' './...' 2>&1
$testExitCode = $LASTEXITCODE

# Save output to file for debugging
$testOutput | Out-File -FilePath "test_output.txt" -Encoding UTF8

# Display output
$testOutput | ForEach-Object { Write-Host $_ }

if ($testExitCode -ne 0) {
    Write-Host ""
    Write-Host "❌ Tests failed!" -ForegroundColor Red
    Write-Host ""
    Write-Host "To debug:"
    Write-Host "  - Check test_output.txt for details"
    Write-Host "  - Run specific test: go test -v -run TestName ./..."
    Remove-Item "test_output.txt" -ErrorAction SilentlyContinue
    exit 1
}

Write-Host ""

# Check if coverage file was generated
if (-not (Test-Path "coverage.out")) {
    Write-Host "❌ coverage.out not generated" -ForegroundColor Red
    exit 1
}

# Calculate overall coverage
Write-Host "📊 Analyzing coverage..." -ForegroundColor Cyan
$coverageOutput = go tool cover '-func=coverage.out' | Select-String "total:"
if ($coverageOutput) {
    $totalCoverage = [regex]::Match($coverageOutput.ToString(), '(\d+\.?\d*)%').Groups[1].Value
    $totalCoverage = [double]$totalCoverage
} else {
    Write-Host "❌ Failed to calculate coverage" -ForegroundColor Red
    exit 1
}

Write-Host "Overall coverage: $totalCoverage%"

# Check baseline coverage
if ($totalCoverage -lt $BASELINE_COVERAGE) {
    Write-Host "❌ Coverage $totalCoverage% is below baseline $BASELINE_COVERAGE%" -ForegroundColor Red
    Write-Host ""
    Write-Host "To improve coverage:"
    Write-Host "  1. View coverage report: go tool cover -html=coverage.out"
    Write-Host "  2. Identify uncovered code: go tool cover -func=coverage.out | Select-String -NotMatch '100.0%'"
    Write-Host "  3. Add tests for uncovered functions"
    exit 1
}

Write-Host "✅ Baseline coverage check passed ($totalCoverage% >= $BASELINE_COVERAGE%)" -ForegroundColor Green
Write-Host ""

# Check incremental coverage (for changed files)
try {
    git rev-parse --git-dir 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "📈 Checking incremental coverage for changed files..." -ForegroundColor Cyan

        # Get list of changed Go files (excluding test files)
        $changedFilesRaw = git diff --name-only --diff-filter=ACM HEAD 2>&1
        $changedFiles = $changedFilesRaw | Where-Object { $_ -match '\.go$' -and $_ -notmatch '_test\.go$' }

        if (-not $changedFiles) {
            Write-Host "ℹ️  No changed Go files found (excluding tests)" -ForegroundColor Gray
            Write-Host "✅ Incremental coverage check skipped" -ForegroundColor Green
        } else {
            Write-Host "Changed files:"
            $changedFiles | ForEach-Object { Write-Host "  - $_" }
            Write-Host ""

            # Extract coverage for changed files
            $failedFiles = @()

            foreach ($file in $changedFiles) {
                if (Test-Path $file) {
                    # Get coverage for this file
                    $fileCoverageLines = go tool cover '-func=coverage.out' | Select-String "/${file}:"

                    if ($fileCoverageLines) {
                        # Calculate average coverage for the file
                        $coverageValues = @()
                        $fileCoverageLines | ForEach-Object {
                            if ($_ -match '(\d+\.?\d*)%') {
                                $coverageValues += [double]$matches[1]
                            }
                        }

                        if ($coverageValues.Count -gt 0) {
                            $fileCoverage = ($coverageValues | Measure-Object -Average).Average
                        } else {
                            $fileCoverage = 0
                        }
                    } else {
                        $fileCoverage = 0
                    }

                    if ($fileCoverage -eq 0) {
                        Write-Host "  ⚠️  $file`: no coverage data" -ForegroundColor Yellow
                        $failedFiles += "$file (no coverage)"
                    } elseif ($fileCoverage -lt $INCREMENTAL_COVERAGE) {
                        Write-Host "  ❌ $file`: $fileCoverage% (< $INCREMENTAL_COVERAGE%)" -ForegroundColor Red
                        $failedFiles += "$file ($fileCoverage%)"
                    } else {
                        Write-Host "  ✅ $file`: $fileCoverage%" -ForegroundColor Green
                    }
                }
            }

            Write-Host ""

            if ($failedFiles.Count -gt 0) {
                Write-Host "❌ Incremental coverage check failed for $($failedFiles.Count) file(s):" -ForegroundColor Red
                $failedFiles | ForEach-Object { Write-Host "  - $_" }
                Write-Host ""
                Write-Host "To improve incremental coverage:"
                Write-Host "  1. View coverage: go tool cover -html=coverage.out"
                Write-Host "  2. Focus on changed files listed above"
                Write-Host "  3. Add tests to reach $INCREMENTAL_COVERAGE% coverage"
                exit 1
            }

            Write-Host "✅ Incremental coverage check passed (all changed files >= $INCREMENTAL_COVERAGE%)" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "ℹ️  Not a git repository - skipping incremental coverage check" -ForegroundColor Gray
}

Write-Host ""

# Generate coverage report
Write-Host "📄 Coverage report:" -ForegroundColor Cyan
go tool cover '-func=coverage.out' | Select-Object -Last 20 | ForEach-Object { Write-Host $_ }

Write-Host ""
Write-Host "✅ All coverage checks passed!" -ForegroundColor Green
Write-Host ""
Write-Host "View detailed coverage:"
Write-Host "  go tool cover -html=coverage.out"

# Cleanup
Remove-Item "test_output.txt" -ErrorAction SilentlyContinue
