# Security Fix Automation - Quick Start Guide

Automatically detect and fix security issues in your Go projects.

## Overview

The security fix automation system provides:
- **Automated scanning** with gosec
- **Intelligent fixes** using AI-powered agents
- **Iterative verification** to ensure fixes work
- **Detailed reports** for tracking progress

## Quick Start

### 1. Run Security Scan

**Linux/macOS:**
```bash
bash .claude/skills/local-ci-go/scripts/run_security.sh
```

**Windows:**
```powershell
.\.claude\skills\local-ci-go\scripts\run_security.ps1
```

### 2. Auto-Fix Issues (if found)

**Linux/macOS:**
```bash
bash .claude/skills/local-ci-go/scripts/security-fix/orchestrator.sh --auto-fix
```

**Windows:**
```powershell
.\.claude\skills\local-ci-go\scripts\security-fix\orchestrator.ps1 -AutoFix
```

### 3. Review & Commit

```bash
# Review changes
git diff

# Run tests
go test ./...

# Commit if satisfied
git add -A
git commit -m "fix: address security issues"
```

## What Gets Fixed Automatically?

| Issue | Auto-Fix | Description |
|-------|----------|-------------|
| **G101** | ✅ Yes | Hardcoded credentials → Environment variables |
| **G104** | ✅ Yes | Unhandled errors → Proper error handling |
| **G304** | ✅ Yes | Path traversal → Path validation |
| **G401-G406** | ✅ Yes | Weak crypto → Strong algorithms |
| **G201/G202** | ⚠️ Review | SQL injection (requires manual review) |
| **G102** | ⚠️ Review | Bind to all interfaces (context-dependent) |

## Example Workflow

```bash
# 1. Scan for issues
$ bash .claude/skills/local-ci-go/scripts/run_security.sh
❌ Security issues detected!
Found 5 issue(s)

# 2. Run auto-fix
$ bash .claude/skills/local-ci-go/scripts/security-fix/orchestrator.sh --auto-fix
🛡️  Security Fix Orchestrator
[Step 1/4] Running security scan...
📊 Found 5 security issue(s)

[Step 2/4] Attempting automatic fixes...
🔧 Fix Iteration 1/3
✓ Fixes applied

[Step 3/4] Verifying fixes...
✅ All issues fixed and verified!

[Step 4/4] Generating final report...
✅ All security issues fixed successfully!

📄 Final report: .ci-temp/security-fix-final-report.md

Next steps:
  1. Review the changes: git diff
  2. Run tests: go test ./...
  3. Commit changes: git add -A && git commit -m 'fix: address security issues'
```

## Reports Generated

All reports are saved to `.ci-temp/`:

```
.ci-temp/
├── gosec-report.json                 # Raw scan results
├── security-scan-summary.md          # Human-readable summary
├── security-fixes-iter1.md           # Fixes applied
├── verification-report-iter1.md      # Verification results
└── security-fix-final-report.md      # Final consolidated report
```

## Options

### Orchestrator Options

**Bash:**
```bash
--auto-fix            # Enable auto-fix without prompting
--no-interactive      # Run without any user input
--max-iterations N    # Maximum fix attempts (default: 3)
```

**PowerShell:**
```powershell
-AutoFix              # Enable auto-fix without prompting
-NoInteractive        # Run without any user input
-MaxIterations N      # Maximum fix attempts (default: 3)
```

### Examples

```bash
# Interactive mode (asks for confirmation)
bash orchestrator.sh

# Fully automatic mode
bash orchestrator.sh --auto-fix --no-interactive

# Limit to 1 iteration
bash orchestrator.sh --auto-fix --max-iterations 1
```

## Integration

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

if ! bash .claude/skills/local-ci-go/scripts/run_security.sh --quiet; then
    echo "Security issues detected. Run auto-fix? (y/n)"
    read response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        bash .claude/skills/local-ci-go/scripts/security-fix/orchestrator.sh --auto-fix
    else
        exit 1
    fi
fi
```

### CI/CD Pipeline

```yaml
# .github/workflows/security.yml
name: Security Check

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Install tools
        run: bash .claude/skills/local-ci-go/scripts/install_tools.sh

      - name: Security scan and fix
        run: |
          bash .claude/skills/local-ci-go/scripts/security-fix/orchestrator.sh \
            --auto-fix \
            --no-interactive

      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: .ci-temp/*.md
```

## Manual Fixes

For issues that can't be auto-fixed, consult:
- `.ci-temp/security-scan-summary.md` - Issue details
- `.claude/skills/local-ci-go/references/security-best-practices.md` - Fix guidance

## Troubleshooting

### "No fixes were applied"

**Cause:** Issues may require manual review or context

**Solution:** Check `.ci-temp/security-fixes-iter1.md` for skipped issues

### "Verification failed"

**Cause:** Fixes may have syntax errors

**Solution:**
```bash
# Check for syntax errors
go fmt ./...
go build ./...

# Review changes
git diff

# Run tests
go test ./...
```

### "Max iterations reached"

**Cause:** Complex issues that need manual intervention

**Solution:** Review `.ci-temp/security-fix-final-report.md` and fix remaining issues manually

## Best Practices

1. **Run locally before pushing** to catch issues early
2. **Review all auto-fixes** - don't blindly commit
3. **Run tests after fixes** to ensure nothing broke
4. **Start with 1-2 iterations** when testing
5. **Use interactive mode first** to see what gets fixed
6. **Keep git commits small** - one fix type per commit

## Learn More

- [Full Documentation](scripts/security-fix/README.md)
- [Security Best Practices](references/security-best-practices.md)
- [Gosec Rules Reference](https://github.com/securego/gosec#available-rules)

## Support

For issues or questions:
1. Check [Troubleshooting](#troubleshooting)
2. Review generated reports in `.ci-temp/`
3. Consult security-best-practices.md
4. Open an issue if the problem persists
