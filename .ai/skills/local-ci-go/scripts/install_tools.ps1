# Install all required tools for CI checks
# PowerShell version for Windows

$ErrorActionPreference = "Stop"

Write-Host "📥 Installing CI tools for Go projects..." -ForegroundColor Cyan
Write-Host ""

# Detect OS and architecture
$OS = "Windows"
$Arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }

Write-Host "Detected: $OS $Arch"
Write-Host ""

# Install gosec
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Installing gosec..." -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

try {
    $null = Get-Command go -ErrorAction Stop
    go install github.com/securego/gosec/v2/cmd/gosec@latest
    Write-Host "✅ gosec installed" -ForegroundColor Green
} catch {
    Write-Host "❌ Go is not installed. Please install Go first: https://go.dev/doc/install" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Install gitleaks
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Installing gitleaks..." -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

try {
    $null = Get-Command gitleaks -ErrorAction Stop
    $version = gitleaks version 2>&1
    Write-Host "✅ gitleaks already installed: $version" -ForegroundColor Green
} catch {
    # Determine download URL based on architecture
    $GitleaksVersion = "8.18.2"

    if ($Arch -eq "x64") {
        $GitleaksURL = "https://github.com/gitleaks/gitleaks/releases/download/v$GitleaksVersion/gitleaks_${GitleaksVersion}_windows_x64.zip"
    } else {
        Write-Host "❌ Unsupported architecture: $Arch" -ForegroundColor Red
        Write-Host "Please install gitleaks manually: https://github.com/gitleaks/gitleaks/releases" -ForegroundColor Yellow
        exit 1
    }

    # Download and install
    $TempDir = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "gitleaks_install_$(Get-Random)")
    $ZipPath = Join-Path $TempDir "gitleaks.zip"

    try {
        Write-Host "Downloading gitleaks from $GitleaksURL..." -ForegroundColor Yellow

        # Download using WebClient (more compatible than Invoke-WebRequest)
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($GitleaksURL, $ZipPath)

        Write-Host "Extracting..." -ForegroundColor Yellow
        Expand-Archive -Path $ZipPath -DestinationPath $TempDir -Force

        # Determine installation directory
        # Try common locations in order of preference
        $InstallLocations = @(
            "$env:LOCALAPPDATA\Programs\gitleaks",
            "$env:USERPROFILE\bin",
            "$env:ProgramFiles\gitleaks"
        )

        $InstallDir = $null
        foreach ($location in $InstallLocations) {
            try {
                if (-not (Test-Path $location)) {
                    New-Item -ItemType Directory -Path $location -Force | Out-Null
                }
                # Test write access
                $testFile = Join-Path $location "test_write_$(Get-Random).tmp"
                Set-Content -Path $testFile -Value "test" -ErrorAction Stop
                Remove-Item $testFile -ErrorAction SilentlyContinue
                $InstallDir = $location
                break
            } catch {
                continue
            }
        }

        if (-not $InstallDir) {
            Write-Host "❌ Could not find a suitable installation directory" -ForegroundColor Red
            Write-Host "Please install gitleaks manually: https://github.com/gitleaks/gitleaks/releases" -ForegroundColor Yellow
            exit 1
        }

        Write-Host "Installing to $InstallDir..." -ForegroundColor Yellow
        Copy-Item -Path (Join-Path $TempDir "gitleaks.exe") -Destination $InstallDir -Force

        # Add to PATH if not already there
        $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
        if ($userPath -notlike "*$InstallDir*") {
            Write-Host "Adding $InstallDir to user PATH..." -ForegroundColor Yellow
            [Environment]::SetEnvironmentVariable(
                "PATH",
                "$userPath;$InstallDir",
                "User"
            )
            # Update current session PATH
            $env:PATH = "$env:PATH;$InstallDir"
        }

        Write-Host "✅ gitleaks installed: $(& "$InstallDir\gitleaks.exe" version 2>&1)" -ForegroundColor Green
        Write-Host "   Location: $InstallDir\gitleaks.exe" -ForegroundColor Gray
        Write-Host "   ⚠️  You may need to restart your terminal for PATH changes to take effect" -ForegroundColor Yellow

    } finally {
        # Cleanup
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""

# Install optional tools
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Installing optional tools..." -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

try {
    $null = Get-Command go-test-coverage -ErrorAction Stop
    Write-Host "✅ go-test-coverage already installed" -ForegroundColor Green
} catch {
    Write-Host "Installing go-test-coverage..." -ForegroundColor Yellow
    go install github.com/vladopajic/go-test-coverage/v2@latest
    Write-Host "✅ go-test-coverage installed" -ForegroundColor Green
}

Write-Host ""

# Verify installations
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Verifying installations..." -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

$AllOK = $true

try {
    $gosecVer = (gosec --version 2>&1 | Select-Object -First 1)
    Write-Host "✅ gosec: $gosecVer" -ForegroundColor Green
} catch {
    Write-Host "❌ gosec: not found" -ForegroundColor Red
    $AllOK = $false
}

try {
    $gitleaksVer = (gitleaks version 2>&1)
    Write-Host "✅ gitleaks: $gitleaksVer" -ForegroundColor Green
} catch {
    Write-Host "❌ gitleaks: not found" -ForegroundColor Red
    Write-Host "   ⚠️  Try restarting your terminal/PowerShell session" -ForegroundColor Yellow
    $AllOK = $false
}

try {
    $null = Get-Command go-test-coverage -ErrorAction Stop
    Write-Host "✅ go-test-coverage: installed" -ForegroundColor Green
} catch {
    Write-Host "⚠️  go-test-coverage: not found (optional)" -ForegroundColor Yellow
}

Write-Host ""

if ($AllOK) {
    Write-Host "🎉 All tools installed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "You can now run CI checks:"
    Write-Host "  PowerShell: .\\.claude\\skills\\local-ci-go\\scripts\\run_all_checks.ps1"
    Write-Host "  Bash:       bash .claude/skills/local-ci-go/scripts/run_all_checks.sh"
    Write-Host ""
} else {
    Write-Host "❌ Some tools failed to install" -ForegroundColor Red
    Write-Host "Please install them manually or check the error messages above" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "If gitleaks is not found after installation, try:" -ForegroundColor Yellow
    Write-Host "  1. Restart your PowerShell/terminal session" -ForegroundColor Yellow
    Write-Host "  2. Or run: refreshenv (if using Chocolatey)" -ForegroundColor Yellow
    Write-Host "  3. Or add the installation directory to your PATH manually" -ForegroundColor Yellow
    exit 1
}
