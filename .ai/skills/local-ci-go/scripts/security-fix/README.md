# Security Fix Automation

Automated security issue detection and fixing system for Go projects.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Main Orchestrator                        │
│                    orchestrator.sh/.ps1                      │
└──────────────┬────────────────────────────────┬─────────────┘
               │                                 │
               ▼                                 ▼
       ┌───────────────┐                ┌───────────────┐
       │  Gosec Scan   │                │   Reports     │
       │  (JSON Output)│──────────────▶ │  Generator    │
       └───────┬───────┘                └───────────────┘
               │
               │ .ci-temp/gosec-report.json
               │
               ▼
       ┌───────────────┐
       │  Fixer Agent  │
       │ (AI-Powered)  │
       └───────┬───────┘
               │
               │ security-fixes.md
               │
               ▼
       ┌───────────────┐
       │ Verifier      │
       │ Agent         │
       └───────┬───────┘
               │
               │ verification-report.md
               │
               ▼
       ┌───────────────┐
       │ Final Report  │
       │  & Decision   │
       └───────────────┘
```

## Components

### 1. Orchestrator (`orchestrator.sh` / `orchestrator.ps1`)

Main controller that coordinates the entire workflow.

**Usage:**
```bash
# Bash
bash .claude/skills/local-ci-go/scripts/security-fix/orchestrator.sh --auto-fix

# PowerShell
.\.claude\skills\local-ci-go\scripts\security-fix\orchestrator.ps1 -AutoFix
```

**Options:**
- `--auto-fix` / `-AutoFix`: Enable automatic fixing without prompts
- `--no-interactive` / `-NoInteractive`: No user input required
- `--max-iterations N` / `-MaxIterations N`: Maximum fix attempts (default: 3)

**Workflow:**
1. Run gosec security scan
2. Generate JSON and markdown reports
3. Ask for auto-fix confirmation (if interactive)
4. Iterate through fix attempts (up to max-iterations)
5. Verify each fix iteration
6. Generate final report with results

### 2. Report Generator (`generate_report.sh` / `generate_report.ps1`)

Converts gosec JSON output to human-readable markdown.

**Usage:**
```bash
bash generate_report.sh .ci-temp/gosec-report.json output.md
```

**Output includes:**
- Summary statistics
- Issues grouped by severity (HIGH, MEDIUM, LOW)
- Issues grouped by rule ID
- Detailed issue breakdown with code snippets

### 3. Fixer Agent (`fixer_agent.sh` / `fixer_agent_claude.sh`)

Applies fixes to code based on gosec findings.

**Two implementations:**

#### Basic Fixer (`fixer_agent.sh`)
- Rule-based fixing
- Pattern matching and replacement
- Limited to simple, well-defined fixes

#### Smart Fixer (`fixer_agent_claude.sh`)
- Uses Claude Code AI agent
- Context-aware fixes
- Handles complex cases
- Automatically falls back to basic fixer if AI unavailable

**Supported Fixes:**
- **G101**: Hardcoded credentials → Environment variables
- **G104**: Unhandled errors → Proper error handling
- **G304**: Path traversal → filepath.Clean() validation
- **G401-G406**: Weak crypto → Strong algorithms (SHA256+)
- **G201/G202**: SQL injection (flagged for manual review)

**Usage:**
```bash
# Basic fixer
bash fixer_agent.sh .ci-temp/gosec-report.json fixes.md

# Smart fixer (uses Claude Code)
bash fixer_agent_claude.sh .ci-temp/gosec-report.json fixes.md
```

### 4. Verifier Agent (`verifier_agent.sh` / `verifier_agent.ps1`)

Validates that fixes were applied correctly by re-running gosec.

**Usage:**
```bash
bash verifier_agent.sh original-report.json fixes-applied.md verification-output.md
```

**Verification Status:**
- **PASS**: All issues fixed, no remaining vulnerabilities
- **PARTIAL**: Some issues fixed, but some remain
- **FAIL**: No progress or new issues introduced

**Output includes:**
- Fix rate percentage
- Remaining issue count and details
- Issue breakdown by severity and rule
- Recommendations for next steps

## Temporary Files

All temporary files are stored in `.ci-temp/`:

```
.ci-temp/
├── gosec-report.json              # Initial scan results
├── gosec-reverify.json            # Verification scan results
├── security-scan-summary.md       # Human-readable summary
├── security-fixes-iter1.md        # Fixes applied in iteration 1
├── security-fixes-iter2.md        # Fixes applied in iteration 2
├── verification-report-iter1.md   # Verification results iteration 1
├── verification-report-iter2.md   # Verification results iteration 2
└── security-fix-final-report.md   # Final consolidated report
```

## Integration with CI/CD

### GitHub Actions

```yaml
name: Security Fix

on:
  push:
    branches: [ main, develop ]
  pull_request:

jobs:
  security-fix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Install tools
        run: |
          bash .claude/skills/local-ci-go/scripts/install_tools.sh

      - name: Run security fix orchestrator
        run: |
          bash .claude/skills/local-ci-go/scripts/security-fix/orchestrator.sh \
            --auto-fix \
            --no-interactive \
            --max-iterations 3

      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: .ci-temp/*.md

      - name: Create PR with fixes
        if: failure()
        uses: peter-evans/create-pull-request@v5
        with:
          commit-message: 'fix: address security issues found by gosec'
          title: '🔒 Security: Auto-fix gosec issues'
          body-path: .ci-temp/security-fix-final-report.md
          branch: security-auto-fix
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Running security checks..."

if bash .claude/skills/local-ci-go/scripts/run_security.sh --json-output .ci-temp/gosec-report.json --quiet; then
    echo "✅ No security issues"
    exit 0
else
    echo "⚠️  Security issues detected!"
    echo ""
    echo "Run auto-fix? (y/n)"
    read -r response

    if [[ "$response" =~ ^[Yy]$ ]]; then
        bash .claude/skills/local-ci-go/scripts/security-fix/orchestrator.sh --auto-fix
        exit $?
    else
        echo "Commit aborted. Fix security issues first."
        exit 1
    fi
fi
```

## Configuration

### Gosec Configuration

Create `.gosec.json` in project root:

```json
{
  "exclude": [],
  "severity": "medium",
  "confidence": "medium",
  "exclude-generated": true,
  "output": {
    "format": "json",
    "output": "stdout"
  }
}
```

### Auto-fix Configuration

Create `.ci-temp/autofix-config.json`:

```json
{
  "enabled_rules": ["G101", "G104", "G304", "G401", "G501"],
  "max_iterations": 3,
  "require_confirmation": false,
  "fallback_to_basic": true,
  "verify_after_fix": true
}
```

## Troubleshooting

### Issue: Fixer agent doesn't apply fixes

**Cause**: May be security issues that require manual review (e.g., SQL injection)

**Solution**: Review `.ci-temp/security-fixes-iter*.md` for skipped issues and fix manually

### Issue: Verification fails after fixes applied

**Cause**: Fixes may have syntax errors or introduced new issues

**Solution**:
1. Run `go fmt ./...` to format code
2. Run `go test ./...` to check for breakages
3. Review git diff to see what changed
4. Manually adjust problematic fixes

### Issue: Claude Code agent not available

**Cause**: Claude CLI not installed or not in PATH

**Solution**: Fixer automatically falls back to basic rule-based fixes. For better results, install Claude Code CLI.

### Issue: Max iterations reached but issues remain

**Cause**: Some issues are too complex for auto-fixing

**Solution**:
1. Review `.ci-temp/security-fix-final-report.md`
2. Check `.ci-temp/verification-report-iter*.md` for details
3. Fix remaining issues manually using security-best-practices.md as reference

## Best Practices

1. **Always review auto-fixes** before committing
2. **Run tests** after fixes are applied
3. **Start with fewer iterations** (1-2) for initial testing
4. **Use interactive mode** first to understand what fixes will be applied
5. **Keep security-best-practices.md** updated with project-specific patterns
6. **Commit fixes incrementally** rather than all at once
7. **Document manual fixes** that couldn't be automated

## Dependencies

- **gosec**: Security scanner for Go
- **jq**: JSON processing
- **git**: Version control (for incremental verification)
- **claude** (optional): Claude Code CLI for smart fixes

## Future Enhancements

- [ ] Support for custom fix templates
- [ ] ML-based fix suggestion ranking
- [ ] Integration with IDE plugins
- [ ] Fix confidence scoring
- [ ] Rollback capability for failed fixes
- [ ] Diff-based verification
- [ ] Multi-file refactoring support
- [ ] Performance impact analysis
