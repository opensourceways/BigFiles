---
name: local-ci-go
description: Run CI checks locally for Go projects before pushing code. Includes unit test coverage validation (10% baseline, 80% incremental), security scanning with Gosec, and sensitive information detection with Gitleaks. Use when you want to verify code quality, catch security issues, or validate test coverage before committing. Triggers on requests like "run CI checks", "check test coverage", "scan for secrets", "run security checks", or any mention of local CI validation for Go projects. Supports Linux, macOS, and Windows.
---

# Local CI for Go Projects

Run comprehensive CI checks locally to catch issues before pushing code.

## Overview

This skill provides three essential CI checks for Go projects:

1. **Unit Test Coverage** - Validate test coverage meets thresholds
   - Baseline: 10% overall coverage
   - Incremental: 80% coverage for new/changed code
   - Tool: `go test --cover`

2. **Security Scanning** - Detect security vulnerabilities in Go code
   - Tool: `gosec`
   - Checks: SQL injection, weak crypto, command injection, etc.

3. **Sensitive Information Detection** - Prevent secrets from being committed
   - Tool: `gitleaks`
   - Detects: API keys, passwords, tokens, private keys, etc.

**Platform Support**: Linux, macOS, and Windows

## Quick Start

### First Time Setup

1. **Check prerequisites**:
```bash
bash .claude/skills/local-ci-go/scripts/check_prerequisites.sh
```

2. **Install missing tools**:
```bash
bash .claude/skills/local-ci-go/scripts/install_tools.sh
```

### Running CI Checks

**Run all checks at once**:
```bash
bash .claude/skills/local-ci-go/scripts/run_all_checks.sh
```

**Or run individual checks**:
```bash
bash .claude/skills/local-ci-go/scripts/run_tests.sh      # Test coverage
bash .claude/skills/local-ci-go/scripts/run_security.sh   # Gosec scan
bash .claude/skills/local-ci-go/scripts/run_gitleaks.sh   # Secret detection
```

## Individual CI Checks

### 1. Unit Test Coverage

**Purpose**: Ensure adequate test coverage for code quality

**Coverage Thresholds**:
- **Baseline**: 10% overall project coverage
- **Incremental**: 80% coverage for new/changed code (git diff)

**Requirements**:
- Go installed
- Test files (`*_test.go`)

**Usage**:
```bash
bash .claude/skills/local-ci-go/scripts/run_tests.sh
```

**What it does**:
1. Runs all tests with coverage: `go test -coverprofile=coverage.out ./...`
2. Checks overall coverage meets 10% threshold
3. Analyzes git diff to identify changed code
4. Validates changed code has 80% coverage
5. Generates detailed coverage report

**Common fixes**:
- Low baseline coverage: Add more unit tests
- Low incremental coverage: Add tests for new/changed functions
- View coverage details: `go tool cover -html=coverage.out`
- See uncovered lines: `go tool cover -func=coverage.out`

### 2. Security Scanning (Gosec)

**Purpose**: Identify security vulnerabilities in Go code

**Requirements**:
- `gosec` installed: `go install github.com/securego/gosec/v2/cmd/gosec@latest`
- Or use install script

**Usage**:
```bash
bash .claude/skills/local-ci-go/scripts/run_security.sh
```

**What it checks**:
- G101: Hardcoded credentials
- G102: Bind to all interfaces
- G104: Unhandled errors
- G201/G202: SQL injection
- G304: File path traversal
- G401-G406: Weak cryptography
- And 50+ other security issues

**Common fixes**:
- **Weak crypto (G401)**: Use SHA256 instead of MD5/SHA1
- **SQL injection (G201)**: Use parameterized queries
- **File traversal (G304)**: Validate paths with `filepath.Clean()`
- **Unhandled errors (G104)**: Always check error return values

See [references/security-best-practices.md](references/security-best-practices.md) for detailed fixes.

### 3. Sensitive Information Detection (Gitleaks)

**Purpose**: Prevent secrets and credentials from being committed

**Requirements**:
- `gitleaks` installed: Download from https://github.com/gitleaks/gitleaks/releases
- Or use install script

**Usage**:
```bash
bash .claude/skills/local-ci-go/scripts/run_gitleaks.sh
```

**What it detects**:
- API keys (AWS, Google, Azure, etc.)
- Authentication tokens (GitHub, GitLab, etc.)
- Database credentials
- Private keys (RSA, SSH, etc.)
- OAuth secrets
- Passwords in code
- JWT tokens
- And 100+ other secret patterns

**Common fixes**:
- **Remove secrets from code**: Use environment variables
- **Use configuration files** (add to .gitignore)
- **If false positive**: Add to `.gitleaksignore`
- **Already committed secrets**: Rotate credentials immediately and remove from git history

**Scan modes**:
```bash
# Scan uncommitted changes only (fast)
bash .claude/skills/local-ci-go/scripts/run_gitleaks.sh

# Scan entire git history (thorough)
bash .claude/skills/local-ci-go/scripts/run_gitleaks.sh history
```

## Configuration

### Test Coverage Thresholds

Edit thresholds in `scripts/run_tests.sh`:
```bash
BASELINE_COVERAGE=10    # Overall project coverage (%)
INCREMENTAL_COVERAGE=80 # New/changed code coverage (%)
```

### Gosec Configuration

Create `.gosec.json` in project root to customize:
```json
{
  "exclude": ["G104"],
  "severity": "medium",
  "confidence": "medium"
}
```

### Gitleaks Configuration

Create `.gitleaks.toml` in project root to customize:
```toml
[extend]
useDefault = true

[allowlist]
paths = [
  ".*_test.go",
  "testdata/"
]
```

## Workflow: Fixing CI Failures

### Test Coverage Failures

1. Run coverage check
2. View coverage report: `go tool cover -html=coverage.out`
3. Identify uncovered code: `go tool cover -func=coverage.out | grep -v "100.0%"`
4. Add tests for uncovered functions
5. Re-run to verify

### Security Scan Failures

1. Run security scan
2. Read error details (file, line, issue type)
3. Consult references/security-best-practices.md
4. Apply fix based on issue type
5. Re-run to verify

### Secret Detection Failures

1. Run gitleaks scan
2. Identify the secret (file and line)
3. Remove secret (move to env var or config file)
4. If already committed: Rotate credential immediately
5. Re-run to verify

## Integration with GitHub Actions

Create `.github/workflows/ci.yml`:
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

## Troubleshooting

**Script not found**:
- Ensure you're in project root
- Check: `ls .claude/skills/local-ci-go/scripts/`

**Permission denied**:
- Make executable: `chmod +x .claude/skills/local-ci-go/scripts/*.sh`

**Tool not installed**:
- Run: `bash .claude/skills/local-ci-go/scripts/install_tools.sh`

**Coverage calculation fails**:
- Ensure tests exist: `find . -name "*_test.go"`
- Check tests pass: `go test ./...`

**Incremental coverage fails**:
- Ensure git repo: `git status`
- Commit changes first

**Gosec false positives**:
- Add exclusions to `.gosec.json`
- Use `#nosec` comment (use sparingly)

**Gitleaks false positives**:
- Add to `.gitleaksignore`
- Customize `.gitleaks.toml`

## Best Practices

1. **Run checks before every commit**
2. **Use git hooks** for automation
3. **Focus on incremental coverage** - aim for 80%+ on new code
4. **Never commit secrets** - use environment variables
5. **Fix security issues immediately** - don't ignore gosec warnings
6. **Review coverage reports** - understand what's not tested
7. **Keep tools updated**

## Resources

- [Gosec Rules](https://github.com/securego/gosec#available-rules)
- [Gitleaks Documentation](https://github.com/gitleaks/gitleaks)
- [Go Testing Best Practices](https://go.dev/doc/tutorial/add-a-test)
- [Go Code Coverage](https://go.dev/blog/cover)
