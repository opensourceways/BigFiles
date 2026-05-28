# Run gitleaks to detect secrets and sensitive information
# PowerShell version for Windows

param(
    [ValidateSet("staged", "uncommitted", "history")]
    [string]$ScanMode = "staged"
)

$ErrorActionPreference = "Stop"

Write-Host "🔐 Scanning for secrets and sensitive information..." -ForegroundColor Cyan
Write-Host ""

# Check if gitleaks is installed
try {
    $null = Get-Command gitleaks -ErrorAction Stop
} catch {
    Write-Host "❌ gitleaks is not installed" -ForegroundColor Red
    Write-Host ""
    Write-Host "Install from: https://github.com/gitleaks/gitleaks/releases"
    Write-Host ""
    Write-Host "Or run:"
    Write-Host "  PowerShell: .\\.claude\\skills\\local-ci-go\\scripts\\install_tools.ps1"
    Write-Host "  Bash:       bash .claude/skills/local-ci-go/scripts/install_tools.sh"
    exit 1
}

# Check if this is a git repository
try {
    git rev-parse --git-dir 2>&1 | Out-Null
    $isGitRepo = ($LASTEXITCODE -eq 0)
} catch {
    $isGitRepo = $false
}

if (-not $isGitRepo) {
    Write-Host "⚠️  Not a git repository" -ForegroundColor Yellow
    Write-Host "Gitleaks works best with git repositories"
    Write-Host ""
    Write-Host "Scanning current directory without git history..." -ForegroundColor Yellow

    $gitleaksOutput = gitleaks detect --no-git --verbose 2>&1
    $gitleaksExitCode = $LASTEXITCODE
    $gitleaksOutput | Out-File -FilePath "gitleaks_output.txt" -Encoding UTF8
    $gitleaksOutput | ForEach-Object { Write-Host $_ }

    if ($gitleaksExitCode -eq 0) {
        Write-Host ""
        Write-Host "✅ No secrets detected!" -ForegroundColor Green
        Remove-Item "gitleaks_output.txt" -ErrorAction SilentlyContinue
        exit 0
    } else {
        Write-Host ""
        Write-Host "❌ Secrets detected!" -ForegroundColor Red
        Write-Host ""
        Write-Host "See gitleaks_output.txt for details"
        exit $gitleaksExitCode
    }
}

# Check for custom gitleaks configuration
$ConfigArg = @()
if (Test-Path ".gitleaks.toml") {
    Write-Host "Using custom configuration: .gitleaks.toml"
    $ConfigArg = @("--config", ".gitleaks.toml")
} else {
    Write-Host "Using default gitleaks configuration"
}

Write-Host ""

# gitleaks writes status to stderr; prevent NativeCommandError when $ErrorActionPreference is "Stop"
$ErrorActionPreference = "Continue"

# Run scan based on mode
switch ($ScanMode) {
    "staged" {
        Write-Host "Scanning staged changes (git diff --cached)..." -ForegroundColor Yellow
        Write-Host "This checks files you're about to commit"
        Write-Host ""

        $gitleaksOutput = & gitleaks protect @ConfigArg --staged --verbose 2>&1
        $gitleaksExitCode = $LASTEXITCODE
    }

    "uncommitted" {
        Write-Host "Scanning uncommitted changes (working directory)..." -ForegroundColor Yellow
        Write-Host "This checks all modified files, staged or not"
        Write-Host ""

        $gitleaksOutput = & gitleaks detect @ConfigArg --no-git --verbose 2>&1
        $gitleaksExitCode = $LASTEXITCODE
    }

    "history" {
        Write-Host "Scanning entire git history..." -ForegroundColor Yellow
        Write-Host "⚠️  This may take a while for large repositories" -ForegroundColor Yellow
        Write-Host ""

        $gitleaksOutput = & gitleaks detect @ConfigArg --verbose 2>&1
        $gitleaksExitCode = $LASTEXITCODE
    }
}

# Save and display output
$gitleaksOutput | Out-File -FilePath "gitleaks_output.txt" -Encoding UTF8
$gitleaksOutput | ForEach-Object { Write-Host $_ }

if ($gitleaksExitCode -eq 0) {
    Write-Host ""
    switch ($ScanMode) {
        "staged" { Write-Host "✅ No secrets detected in staged changes!" -ForegroundColor Green }
        "uncommitted" { Write-Host "✅ No secrets detected in uncommitted changes!" -ForegroundColor Green }
        "history" { Write-Host "✅ No secrets detected in git history!" -ForegroundColor Green }
    }
    Remove-Item "gitleaks_output.txt" -ErrorAction SilentlyContinue
    exit 0
}

# If we get here, secrets were detected
Write-Host ""
Write-Host "❌ Secrets detected!" -ForegroundColor Red
Write-Host ""
Write-Host "⚠️  CRITICAL: If these secrets are real, you must:" -ForegroundColor Yellow
Write-Host "  1. Rotate/revoke the compromised credentials IMMEDIATELY"
Write-Host "  2. Remove secrets from code"
Write-Host "  3. If already committed, remove from git history"
Write-Host ""
Write-Host "Common fixes:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Use environment variables:"
Write-Host "   // Bad"
Write-Host '   apiKey := "sk-1234567890abcdef"'
Write-Host ""
Write-Host "   // Good"
Write-Host '   apiKey := os.Getenv("API_KEY")'
Write-Host ""
Write-Host "2. Use configuration files (add to .gitignore):"
Write-Host "   // config.yaml (in .gitignore)"
Write-Host "   api_key: sk-1234567890abcdef"
Write-Host ""
Write-Host "3. Use secret management services:"
Write-Host "   - AWS Secrets Manager"
Write-Host "   - HashiCorp Vault"
Write-Host "   - Azure Key Vault"
Write-Host ""
Write-Host "4. If false positive, add to .gitleaksignore:"
Write-Host "   path/to/file.go:line_number"
Write-Host ""
Write-Host "5. If already committed, remove from history:"
Write-Host "   git filter-branch --force --index-filter \"
Write-Host "     'git rm --cached --ignore-unmatch path/to/file' \"
Write-Host "     --prune-empty --tag-name-filter cat -- --all"
Write-Host ""
Write-Host "   Or use BFG Repo-Cleaner: https://rtyley.github.io/bfg-repo-cleaner/"
Write-Host ""
Write-Host "For detailed information, see:"
Write-Host "  .claude/skills/local-ci-go/references/security-best-practices.md"
Write-Host ""

Remove-Item "gitleaks_output.txt" -ErrorAction SilentlyContinue
exit $gitleaksExitCode
