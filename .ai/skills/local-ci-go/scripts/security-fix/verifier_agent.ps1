# Verifier Agent (PowerShell version)
# Validates that security fixes were applied correctly by re-running gosec

param(
    [Parameter(Mandatory=$true)]
    [string]$OriginalReport,

    [Parameter(Mandatory=$true)]
    [string]$FixesApplied,

    [Parameter(Mandatory=$true)]
    [string]$VerificationOutput
)

$ErrorActionPreference = "Continue"

if (-not (Test-Path $OriginalReport)) {
    Write-Error "Error: $OriginalReport not found"
    exit 1
}

Write-Host "🔍 Verifier Agent: Re-scanning for security issues..." -ForegroundColor Cyan

# Run gosec again
$tempReport = ".ci-temp/gosec-reverify.json"
New-Item -ItemType Directory -Path ".ci-temp" -Force | Out-Null

# Run security scan again
$scriptDir = Split-Path -Parent $PSCommandPath
& "$scriptDir\..\run_security.ps1" -JsonOutput $tempReport -Quiet 2>&1 | Out-Null
$scanExitCode = $LASTEXITCODE

# Parse reports
try {
    $original = Get-Content $OriginalReport | ConvertFrom-Json
    $originalCount = $original.Issues.Count
} catch {
    $originalCount = 0
}

if ($scanExitCode -eq 0) {
    # No issues found - complete success!
    $status = "PASS"
    $newCount = 0
    $fixedCount = $originalCount
} else {
    # Still have issues - compare counts
    try {
        $new = Get-Content $tempReport | ConvertFrom-Json
        $newCount = $new.Issues.Count
    } catch {
        $newCount = $originalCount
    }

    $fixedCount = $originalCount - $newCount

    if ($newCount -eq 0) {
        $status = "PASS"
    } elseif ($newCount -lt $originalCount) {
        $status = "PARTIAL"
    } else {
        $status = "FAIL"
    }
}

# Generate verification report
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$fixRate = if ($originalCount -gt 0) { [math]::Round(($fixedCount / $originalCount) * 100, 1) } else { 0 }

$report = @"
# Verification Report

**Timestamp:** $timestamp UTC
**Status:** $status

## Results

- **Original Issues:** $originalCount
- **Remaining Issues:** $newCount
- **Fixed Issues:** $fixedCount
- **Fix Rate:** ${fixRate}%

"@

switch ($status) {
    "PASS" {
        $report += @"

## ✅ Verification Passed

All security issues have been successfully resolved!

### Summary
- All $originalCount issue(s) fixed
- No remaining vulnerabilities
- Code is ready for commit

"@
    }

    "PARTIAL" {
        $report += @"

## ⚠️ Partial Success

Some issues were fixed, but $newCount issue(s) remain.

### Progress
- Fixed: $fixedCount / $originalCount issue(s)
- Remaining: $newCount issue(s)

### Remaining Issues

"@

        # List remaining issues
        if (Test-Path $tempReport) {
            try {
                $remaining = Get-Content $tempReport | ConvertFrom-Json
                foreach ($issue in $remaining.Issues) {
                    $report += "- **$($issue.RuleID)** in ``$($issue.File):$($issue.Line)`` - $($issue.What)`n"
                }
            } catch {
                $report += "(Unable to parse remaining issues)`n"
            }
        }

        $report += @"

### Recommendation
- Review remaining issues manually
- Run another fix iteration
- Consult security-best-practices.md

"@
    }

    "FAIL" {
        $report += @"

## ❌ Verification Failed

No progress was made in fixing security issues.

### Analysis
- Original issues: $originalCount
- Current issues: $newCount
- Fixes may have introduced new issues or were not applied correctly

### Next Steps
1. Review the fixes that were attempted
2. Check for syntax errors or test failures
3. Consider manual intervention
4. Consult with security expert

"@
    }
}

# Add detailed breakdown if there are still issues
if ($newCount -gt 0 -and (Test-Path $tempReport)) {
    $report += @"

## Detailed Issue Breakdown

### By Severity

"@

    try {
        $new = Get-Content $tempReport | ConvertFrom-Json
        $high = ($new.Issues | Where-Object {$_.Severity -eq "HIGH"} | Measure-Object).Count
        $medium = ($new.Issues | Where-Object {$_.Severity -eq "MEDIUM"} | Measure-Object).Count
        $low = ($new.Issues | Where-Object {$_.Severity -eq "LOW"} | Measure-Object).Count

        $report += @"

| Severity | Count |
|----------|-------|
| 🔴 HIGH   | $high |
| 🟡 MEDIUM | $medium |
| 🟢 LOW    | $low |

### By Rule

"@

        $ruleGroups = $new.Issues | Group-Object -Property RuleID | Sort-Object -Property Count -Descending
        foreach ($group in $ruleGroups) {
            $count = $group.Count
            $ruleId = $group.Name
            $what = $group.Group[0].What
            $report += "- ${count}x **${ruleId}**: $what`n"
        }
    } catch {
        $report += "(Unable to generate breakdown)`n"
    }
}

# Write report
$report | Out-File -FilePath $VerificationOutput -Encoding UTF8

Write-Host "" -ForegroundColor Gray
Write-Host "Verification completed: $status" -ForegroundColor Cyan
Write-Host "  Original: $originalCount issues" -ForegroundColor Gray
Write-Host "  Remaining: $newCount issues" -ForegroundColor Gray
Write-Host "  Fixed: $fixedCount issues" -ForegroundColor Gray
Write-Host "" -ForegroundColor Gray

# Exit codes: 0 = PASS, 1 = PARTIAL/FAIL
if ($status -eq "PASS") {
    exit 0
} else {
    exit 1
}
