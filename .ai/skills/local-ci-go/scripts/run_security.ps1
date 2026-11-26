# Run gosec security scanner to detect vulnerabilities
# PowerShell version for Windows

$ErrorActionPreference = "Stop"

Write-Host "🔒 Running security scan with gosec..." -ForegroundColor Cyan
Write-Host ""

# Check if gosec is installed
try {
    $null = Get-Command gosec -ErrorAction Stop
} catch {
    Write-Host "❌ gosec is not installed" -ForegroundColor Red
    Write-Host ""
    Write-Host "Install with:"
    Write-Host "  go install github.com/securego/gosec/v2/cmd/gosec@latest"
    Write-Host ""
    Write-Host "Or run:"
    Write-Host "  PowerShell: .\\.claude\\skills\\local-ci-go\\scripts\\install_tools.ps1"
    Write-Host "  Bash:       bash .claude/skills/local-ci-go/scripts/install_tools.sh"
    exit 1
}

# Check if go.mod exists
if (-not (Test-Path "go.mod")) {
    Write-Host "❌ go.mod not found. Is this a Go module?" -ForegroundColor Red
    exit 1
}

# Check for custom gosec configuration
$ConfigArg = @()
if (Test-Path ".gosec.json") {
    Write-Host "Using custom configuration: .gosec.json"
    $ConfigArg = @("-conf", ".gosec.json")
} else {
    Write-Host "Using default gosec configuration"
}

Write-Host ""

# Run gosec
Write-Host "Scanning for security vulnerabilities..." -ForegroundColor Yellow
$ErrorActionPreference = "Continue"  # gosec writes status to stderr; prevent NativeCommandError
$gosecOutput = & gosec @ConfigArg -fmt=text ./... 2>&1
$gosecExitCode = $LASTEXITCODE

# Save output to file
$gosecOutput | Out-File -FilePath "gosec_output.txt" -Encoding UTF8

# Display output
$gosecOutput | ForEach-Object { Write-Host $_ }

if ($gosecExitCode -eq 0) {
    Write-Host ""
    Write-Host "✅ No security issues found!" -ForegroundColor Green
    Remove-Item "gosec_output.txt" -ErrorAction SilentlyContinue
    exit 0
} else {
    Write-Host ""
    Write-Host "❌ Security issues detected!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Common fixes:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "G101 - Hardcoded credentials:"
    Write-Host '  Use environment variables: apiKey := os.Getenv("API_KEY")'
    Write-Host ""
    Write-Host "G104 - Unhandled errors:"
    Write-Host "  Always check errors: if err := file.Close(); err != nil { ... }"
    Write-Host ""
    Write-Host "G201/G202 - SQL injection:"
    Write-Host '  Use parameterized queries: db.Query("SELECT * FROM users WHERE id = ?", userId)'
    Write-Host ""
    Write-Host "G304 - File path traversal:"
    Write-Host "  Validate paths: cleanPath := filepath.Clean(userInput)"
    Write-Host ""
    Write-Host "G401-G406 - Weak cryptography:"
    Write-Host "  Use strong algorithms: sha256.New() instead of md5.New()"
    Write-Host ""
    Write-Host "For detailed fixes, see:"
    Write-Host "  .claude/skills/local-ci-go/references/security-best-practices.md"
    Write-Host ""
    Write-Host "To exclude specific issues (use sparingly):"
    Write-Host '  Add #nosec comment: password := "temp" // #nosec G101'
    Write-Host "  Or configure .gosec.json to exclude rule globally"
    Write-Host ""

    Remove-Item "gosec_output.txt" -ErrorAction SilentlyContinue
    exit $gosecExitCode
}
