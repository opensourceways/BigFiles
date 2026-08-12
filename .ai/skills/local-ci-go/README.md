# Local CI for Go Projects

A comprehensive CI skill for Go projects that runs locally before pushing code.

## Features

✅ **Unit Test Coverage Validation**
- 10% baseline coverage requirement
- 80% incremental coverage for changed code
- Detailed coverage reports

✅ **Security Scanning (Gosec)**
- Detects SQL injection vulnerabilities
- Identifies weak cryptography usage
- Finds hardcoded credentials
- Checks for command injection risks
- And 50+ other security issues

✅ **🆕 Automated Security Fixes**
- AI-powered intelligent fix suggestions
- Iterative fix and verify workflow
- Detailed fix reports and tracking
- Supports G101, G104, G304, G401-G406 rules
- See [SECURITY-FIX.md](SECURITY-FIX.md) for details

✅ **Secret Detection (Gitleaks)**
- Scans for API keys and tokens
- Detects passwords and credentials
- Finds private keys
- Prevents secret leaks before commit
- Supports 100+ secret patterns

## Quick Start

### 1. Check Prerequisites

**Linux/macOS:**
```bash
bash .claude/skills/local-ci-go/scripts/check_prerequisites.sh
```

**Windows (PowerShell):**
```powershell
.\.claude\skills\local-ci-go\scripts\check_prerequisites.ps1
```

### 2. Install Missing Tools

**Linux/macOS:**
```bash
bash .claude/skills/local-ci-go/scripts/install_tools.sh
```

**Windows (PowerShell):**
```powershell
.\.claude\skills\local-ci-go\scripts\install_tools.ps1
```

### 3. Run All Checks

**Linux/macOS:**
```bash
bash .claude/skills/local-ci-go/scripts/run_all_checks.sh
```

**Windows (PowerShell):**
```powershell
.\.claude\skills\local-ci-go\scripts\run_all_checks.ps1
```

## Individual Checks

Run specific checks independently:

**Linux/macOS:**
```bash
# Test coverage
bash .claude/skills/local-ci-go/scripts/run_tests.sh

# Security scan
bash .claude/skills/local-ci-go/scripts/run_security.sh

# Secret detection
bash .claude/skills/local-ci-go/scripts/run_gitleaks.sh
```

**Windows (PowerShell):**
```powershell
# Test coverage
.\.claude\skills\local-ci-go\scripts\run_tests.ps1

# Security scan
.\.claude\skills\local-ci-go\scripts\run_security.ps1

# Secret detection
.\.claude\skills\local-ci-go\scripts\run_gitleaks.ps1

# Secret detection with different modes
.\.claude\skills\local-ci-go\scripts\run_gitleaks.ps1 -ScanMode staged
.\.claude\skills\local-ci-go\scripts\run_gitleaks.ps1 -ScanMode uncommitted
.\.claude\skills\local-ci-go\scripts\run_gitleaks.ps1 -ScanMode history
```

## Configuration

### Coverage Thresholds

Edit `scripts/run_tests.sh`:
```bash
BASELINE_COVERAGE=10    # Overall project coverage (%)
INCREMENTAL_COVERAGE=80 # New/changed code coverage (%)
```

### Gosec Configuration

Create `.gosec.json` in project root:
```json
{
  "exclude": ["G104"],
  "severity": "medium",
  "confidence": "medium"
}
```

### Gitleaks Configuration

Create `.gitleaks.toml` in project root:
```toml
[extend]
useDefault = true

[allowlist]
paths = [
  ".*_test.go",
  "testdata/"
]
```

## Pre-commit Hook

Automate checks before every commit:

```bash
# Create pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
bash .claude/skills/local-ci-go/scripts/run_all_checks.sh
EOF

chmod +x .git/hooks/pre-commit
```

## GitHub Actions Integration

Add to `.github/workflows/ci.yml`:

```yaml
name: CI

on: [push, pull_request]

jobs:
  test-coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Run tests with coverage
        run: |
          go test -coverprofile=coverage.out ./...
          total=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
          if (( $(echo "$total < 10" | bc -l) )); then
            echo "Coverage $total% is below 10%"
            exit 1
          fi

  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      - name: Run Gosec
        uses: securego/gosec@master
        with:
          args: ./...

  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Security Auto-Fix

When security issues are found, you can automatically fix them:

**Linux/macOS:**
```bash
bash .claude/skills/local-ci-go/scripts/security-fix/orchestrator.sh --auto-fix
```

**Windows:**
```powershell
.\.claude\skills\local-ci-go\scripts\security-fix\orchestrator.ps1 -AutoFix
```

See [SECURITY-FIX.md](SECURITY-FIX.md) for complete documentation.

## Troubleshooting

### Tool Not Found

```bash
# Install all tools
bash .claude/skills/local-ci-go/scripts/install_tools.sh

# Or install individually
go install github.com/securego/gosec/v2/cmd/gosec@latest
# Download gitleaks from: https://github.com/gitleaks/gitleaks/releases
```

### Coverage Calculation Fails

```bash
# Ensure tests exist
find . -name "*_test.go"

# Run tests manually
go test ./...
```

### False Positives

**Gosec**: Add `#nosec` comment or configure `.gosec.json`
**Gitleaks**: Add to `.gitleaksignore` or configure `.gitleaks.toml`

## Documentation

- [SKILL.md](SKILL.md) - Complete skill documentation
- [references/security-best-practices.md](references/security-best-practices.md) - Security fixes and best practices

## Requirements

- Go 1.16+
- Git (for incremental coverage)
- Linux, macOS, or Windows

## Tools Installed

- **gosec** - Security scanner for Go
- **gitleaks** - Secret detection tool
- **go-test-coverage** (optional) - Enhanced coverage reports

## License

This skill is part of the Claude Code skills ecosystem.
