# Security Fix Orchestrator (PowerShell)
# Coordinates the security scan, fix, and verification workflow

param(
    [switch]$AutoFix,
    [switch]$NoInteractive,
    [int]$MaxIterations = 3
)

$ErrorActionPreference = "Stop"

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$PROJECT_ROOT = (Get-Item $SCRIPT_DIR).Parent.Parent.FullName
$TEMP_DIR = ".ci-temp"

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "🛡️  Security Fix Orchestrator" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

# Create temp directory
New-Item -ItemType Directory -Path $TEMP_DIR -Force | Out-Null

# Step 1: Run gosec scan and generate report
Write-Host "[Step 1/4] Running security scan..." -ForegroundColor Blue
Write-Host ""

$jsonOutput = Join-Path $TEMP_DIR "gosec-report.json"
& "$SCRIPT_DIR\..\run_security.ps1" -JsonOutput $jsonOutput -Quiet

$scanExitCode = $LASTEXITCODE

if ($scanExitCode -eq 0) {
    Write-Host "✅ No security issues found!" -ForegroundColor Green
    exit 0
}

Write-Host "⚠️  Security issues detected (exit code: $scanExitCode)" -ForegroundColor Yellow

# Parse report to get issue count
try {
    $report = Get-Content $jsonOutput | ConvertFrom-Json
    $issueCount = $report.Issues.Count
} catch {
    $issueCount = 0
}

Write-Host "📊 Found $issueCount security issue(s)" -ForegroundColor Yellow
Write-Host ""

# Generate human-readable summary
& "$SCRIPT_DIR\generate_report.ps1" $jsonOutput "$TEMP_DIR\security-scan-summary.md"

Write-Host "✓ Report generated: $TEMP_DIR\security-scan-summary.md" -ForegroundColor Green
Write-Host ""

# Display summary
if (Test-Path "$TEMP_DIR\security-scan-summary.md") {
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Get-Content "$TEMP_DIR\security-scan-summary.md" | Select-Object -First 50 | ForEach-Object { Write-Host $_ }
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host ""
}

# Ask user if they want to auto-fix
if (-not $AutoFix -and -not $NoInteractive) {
    Write-Host "Do you want to attempt automatic fixes? (y/n)" -ForegroundColor Yellow
    $response = Read-Host
    if ($response -notmatch '^[Yy]$') {
        Write-Host "Fix cancelled by user"
        exit 1
    }
    $AutoFix = $true
}

if (-not $AutoFix) {
    Write-Host "⚠️  Auto-fix not enabled. Run with -AutoFix to attempt automatic fixes." -ForegroundColor Yellow
    exit 1
}

# Step 2-4: Iterative fixing and verification
Write-Host "[Step 2/4] Attempting automatic fixes..." -ForegroundColor Blue
Write-Host ""

$iteration = 1
$fixSuccess = $false

while ($iteration -le $MaxIterations) {
    Write-Host "🔧 Fix Iteration $iteration/$MaxIterations" -ForegroundColor Cyan

    try {
        & "$SCRIPT_DIR\fixer_agent.ps1" $jsonOutput "$TEMP_DIR\security-fixes-iter$iteration.md"
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ Fixes applied" -ForegroundColor Green

            # Step 3: Verify fixes
            Write-Host ""
            Write-Host "[Step 3/4] Verifying fixes..." -ForegroundColor Blue
            Write-Host ""

            & "$SCRIPT_DIR\verifier_agent.ps1" $jsonOutput "$TEMP_DIR\security-fixes-iter$iteration.md" "$TEMP_DIR\verification-report-iter$iteration.md"

            if ($LASTEXITCODE -eq 0) {
                $verificationContent = Get-Content "$TEMP_DIR\verification-report-iter$iteration.md" -Raw
                if ($verificationContent -match 'Status:\s+(\w+)') {
                    $verificationResult = $matches[1]
                } else {
                    $verificationResult = "UNKNOWN"
                }

                switch ($verificationResult) {
                    "PASS" {
                        Write-Host "✅ All issues fixed and verified!" -ForegroundColor Green
                        $fixSuccess = $true
                        break
                    }
                    "PARTIAL" {
                        if ($verificationContent -match 'Remaining Issues:\s+(\d+)') {
                            $remaining = $matches[1]
                        } else {
                            $remaining = "unknown"
                        }
                        Write-Host "⚠️  Partial fix: $remaining issue(s) remaining" -ForegroundColor Yellow

                        if ($iteration -lt $MaxIterations) {
                            Write-Host "🔄 Attempting another fix iteration..." -ForegroundColor Yellow
                            Write-Host ""
                        }
                    }
                    default {
                        Write-Host "❌ Verification failed" -ForegroundColor Red
                        break
                    }
                }
            } else {
                Write-Host "❌ Verification step failed" -ForegroundColor Red
                break
            }
        } else {
            Write-Host "❌ Fix attempt failed" -ForegroundColor Red
            break
        }
    } catch {
        Write-Host "❌ Error during fix iteration: $_" -ForegroundColor Red
        break
    }

    $iteration++
}

# Step 4: Generate final report
Write-Host ""
Write-Host "[Step 4/4] Generating final report..." -ForegroundColor Blue
Write-Host ""

$finalReport = "$TEMP_DIR\security-fix-final-report.md"

if ($fixSuccess) {
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
    Write-Host "✅ All security issues fixed successfully!" -ForegroundColor Green
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
    Write-Host ""
    Write-Host "📄 Final report: $finalReport" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Review the changes: git diff"
    Write-Host "  2. Run tests: go test ./..."
    Write-Host "  3. Commit changes: git add -A && git commit -m 'fix: address security issues'"
    Write-Host ""
    exit 0
} else {
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
    Write-Host "⚠️  Could not fix all issues automatically" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "📄 Final report: $finalReport" -ForegroundColor Cyan
    Write-Host "📄 Remaining issues: $TEMP_DIR\security-scan-summary.md" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Manual fixes required. See report for details." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}
