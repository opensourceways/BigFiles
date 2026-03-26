# Generate human-readable security report from gosec JSON output
# PowerShell version

param(
    [Parameter(Mandatory=$true)]
    [string]$GosecJson,

    [Parameter(Mandatory=$true)]
    [string]$OutputMd
)

if (-not (Test-Path $GosecJson)) {
    Write-Error "Error: $GosecJson not found"
    exit 1
}

# Parse JSON
try {
    $report = Get-Content $GosecJson | ConvertFrom-Json
} catch {
    Write-Error "Failed to parse JSON: $_"
    exit 1
}

# Generate markdown
$issueCount = $report.Issues.Count

$md = @"
# Security Scan Report

**Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") UTC

## Summary

- **Total Issues:** $issueCount
- **Scan Tool:** gosec

### By Severity

"@

# Group by severity
$highCount = ($report.Issues | Where-Object {$_.Severity -eq "HIGH"} | Measure-Object).Count
$mediumCount = ($report.Issues | Where-Object {$_.Severity -eq "MEDIUM"} | Measure-Object).Count
$lowCount = ($report.Issues | Where-Object {$_.Severity -eq "LOW"} | Measure-Object).Count

$md += @"

| Severity | Count |
|----------|-------|
| 🔴 HIGH   | $highCount |
| 🟡 MEDIUM | $mediumCount |
| 🟢 LOW    | $lowCount |

### By Rule

"@

# Group by rule
$ruleGroups = $report.Issues | Group-Object -Property RuleID | Sort-Object -Property Count -Descending

foreach ($group in $ruleGroups) {
    $count = $group.Count
    $ruleId = $group.Name
    $what = $group.Group[0].What
    $md += "- ${count}x ${ruleId}: $what`n"
}

$md += @"

## Detailed Issues

"@

# Add detailed issues
foreach ($issue in $report.Issues) {
    $md += @"

### Issue: $($issue.What)

**Rule:** ``$($issue.RuleID)``
**Severity:** $($issue.Severity)
**Confidence:** $($issue.Confidence)

**Location:** ``$($issue.File):$($issue.Line)``

**Code:**
``````go
$($issue.Code)
``````

**Details:**
$($issue.Details)

---

"@
}

# Write to file
$md | Out-File -FilePath $OutputMd -Encoding UTF8

Write-Host "Report generated: $OutputMd" -ForegroundColor Green
