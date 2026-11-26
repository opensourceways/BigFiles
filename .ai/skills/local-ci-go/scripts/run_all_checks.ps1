# Run all CI checks in sequence
# PowerShell version for Windows

$ErrorActionPreference = "Stop"

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "🚀 Running all CI checks for Go" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

# Check prerequisites first
Write-Host "Step 1: Checking prerequisites..." -ForegroundColor Yellow
Write-Host ""

try {
    & "$SCRIPT_DIR\check_prerequisites.ps1"
    $prereqExitCode = $LASTEXITCODE
} catch {
    $prereqExitCode = 1
}

if ($prereqExitCode -ne 0) {
    Write-Host ""
    Write-Host "❌ Prerequisites check failed!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install missing tools first:"
    Write-Host "  PowerShell: .\\.claude\\skills\\local-ci-go\\scripts\\install_tools.ps1"
    Write-Host "  Bash:       bash .claude/skills/local-ci-go/scripts/install_tools.sh"
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "Step 2: Running CI checks..." -ForegroundColor Yellow
Write-Host ""

# Track failures
$FailedChecks = @()
$PassedChecks = @()

# Function to run a check
function Run-Check {
    param(
        [string]$CheckName,
        [string]$ScriptName
    )

    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "▶️  Running: $CheckName" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

    try {
        & "$SCRIPT_DIR\$ScriptName"
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            $script:PassedChecks += $CheckName
            Write-Host ""
        } else {
            $script:FailedChecks += $CheckName
            Write-Host "❌ $CheckName failed!" -ForegroundColor Red
            Write-Host ""
        }
    } catch {
        $script:FailedChecks += $CheckName
        Write-Host "❌ $CheckName failed!" -ForegroundColor Red
        Write-Host ""
    }
}

# Run all checks
Run-Check "Unit Test Coverage" "run_tests.ps1"
Run-Check "Security Scan (Gosec)" "run_security.ps1"
Run-Check "Secret Detection (Gitleaks)" "run_gitleaks.ps1"

# Summary
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "📊 CI Checks Summary" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

if ($PassedChecks.Count -gt 0) {
    Write-Host "✅ Passed ($($PassedChecks.Count)):" -ForegroundColor Green
    foreach ($check in $PassedChecks) {
        Write-Host "   - $check"
    }
    Write-Host ""
}

if ($FailedChecks.Count -gt 0) {
    Write-Host "❌ Failed ($($FailedChecks.Count)):" -ForegroundColor Red
    foreach ($check in $FailedChecks) {
        Write-Host "   - $check"
    }
    Write-Host ""
    Write-Host "Run individual checks to see detailed error messages:"
    foreach ($check in $FailedChecks) {
        switch ($check) {
            "Unit Test Coverage" {
                Write-Host "   PowerShell: .\\.claude\\skills\\local-ci-go\\scripts\\run_tests.ps1"
                Write-Host "   Bash:       bash .claude/skills/local-ci-go/scripts/run_tests.sh"
            }
            "Security Scan (Gosec)" {
                Write-Host "   PowerShell: .\\.claude\\skills\\local-ci-go\\scripts\\run_security.ps1"
                Write-Host "   Bash:       bash .claude/skills/local-ci-go/scripts/run_security.sh"
            }
            "Secret Detection (Gitleaks)" {
                Write-Host "   PowerShell: .\\.claude\\skills\\local-ci-go\\scripts\\run_gitleaks.ps1"
                Write-Host "   Bash:       bash .claude/skills/local-ci-go/scripts/run_gitleaks.sh"
            }
        }
    }
    Write-Host ""
    exit 1
}

Write-Host "🎉 All CI checks passed!" -ForegroundColor Green
Write-Host ""
Write-Host "Your code is ready to commit and push!"
