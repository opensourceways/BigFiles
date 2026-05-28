# Check all prerequisites for CI checks before running
# PowerShell version for Windows

Write-Host "🔍 Checking prerequisites for local CI checks..." -ForegroundColor Cyan
Write-Host ""

$MissingTools = @()
$AllOK = $true

# Check for required tools
Write-Host "📦 Checking installed tools:"

# Check Go
try {
    $goVersion = go version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✅ go: $goVersion" -ForegroundColor Green
    } else {
        throw
    }
} catch {
    Write-Host "  ❌ go: not installed" -ForegroundColor Red
    $MissingTools += "go"
    $AllOK = $false
}

# Check gosec
try {
    $gosecVersion = (gosec --version 2>&1 | Select-Object -First 1)
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✅ gosec: $gosecVersion" -ForegroundColor Green
    } else {
        throw
    }
} catch {
    Write-Host "  ❌ gosec: not installed" -ForegroundColor Red
    $MissingTools += "gosec"
    $AllOK = $false
}

# Check gitleaks
try {
    $gitleaksVersion = (gitleaks version 2>&1)
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✅ gitleaks: $gitleaksVersion" -ForegroundColor Green
    } else {
        throw
    }
} catch {
    Write-Host "  ❌ gitleaks: not installed" -ForegroundColor Red
    $MissingTools += "gitleaks"
    $AllOK = $false
}

Write-Host ""

# Check for optional tools
Write-Host "📦 Checking optional tools:"

try {
    $null = Get-Command go-test-coverage -ErrorAction Stop
    Write-Host "  ✅ go-test-coverage: installed" -ForegroundColor Green
} catch {
    Write-Host "  ⚠️  go-test-coverage: not installed (optional, for better coverage reports)" -ForegroundColor Yellow
}

Write-Host ""

# Check for git repository
Write-Host "📁 Checking project setup:"

try {
    git rev-parse --git-dir 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✅ git repository: initialized" -ForegroundColor Green
    } else {
        throw
    }
} catch {
    Write-Host "  ⚠️  git repository: not initialized (needed for incremental coverage)" -ForegroundColor Yellow
    Write-Host "     Run: git init"
}

# Check for Go module
if (Test-Path "go.mod") {
    Write-Host "  ✅ go.mod: found" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  go.mod: not found" -ForegroundColor Yellow
    Write-Host "     Run: go mod init <module-name>"
}

# Check for test files
$testFiles = Get-ChildItem -Recurse -Filter "*_test.go" -File -ErrorAction SilentlyContinue
if ($testFiles.Count -gt 0) {
    Write-Host "  ✅ test files: found ($($testFiles.Count) files)" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  test files: no *_test.go files found" -ForegroundColor Yellow
}

Write-Host ""

# Summary and recommendations
if ($AllOK) {
    Write-Host "🎉 All required tools are installed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "You can now run CI checks:"
    Write-Host "  PowerShell: .\\.claude\\skills\\local-ci-go\\scripts\\run_all_checks.ps1"
    Write-Host "  Bash:       bash .claude/skills/local-ci-go/scripts/run_all_checks.sh"
    Write-Host ""
    exit 0
} else {
    Write-Host "❌ Some required tools are missing!" -ForegroundColor Red
    Write-Host ""

    if ($MissingTools.Count -gt 0) {
        Write-Host "📥 Missing tools that need to be installed:"
        foreach ($tool in $MissingTools) {
            Write-Host "  - $tool"
        }
        Write-Host ""
        Write-Host "To install all missing tools, run:"
        Write-Host "  PowerShell: .\\.claude\\skills\\local-ci-go\\scripts\\install_tools.ps1"
        Write-Host "  Bash:       bash .claude/skills/local-ci-go/scripts/install_tools.sh"
        Write-Host ""
        Write-Host "Or install individually:"
        foreach ($tool in $MissingTools) {
            switch ($tool) {
                "go" {
                    Write-Host "  - go: https://go.dev/doc/install"
                }
                "gosec" {
                    Write-Host "  - gosec: go install github.com/securego/gosec/v2/cmd/gosec@latest"
                }
                "gitleaks" {
                    Write-Host "  - gitleaks: https://github.com/gitleaks/gitleaks/releases"
                }
            }
        }
        Write-Host ""
    }

    exit 1
}
