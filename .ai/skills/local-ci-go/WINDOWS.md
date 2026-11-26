# Windows Setup Guide for local-ci-go

This guide helps Windows users set up and use the local-ci-go skill.

## Prerequisites

- **PowerShell 5.1+** (pre-installed on Windows 10/11)
- **Go 1.16+** - Download from https://go.dev/doc/install
- **Git** - Download from https://git-scm.com/download/win

## Quick Start

### 1. Open PowerShell

Right-click on the Start menu and select:
- **Windows PowerShell** (Windows 10)
- **Terminal** (Windows 11)

Navigate to your Go project directory:
```powershell
cd path\to\your\project
```

### 2. Check Prerequisites

```powershell
.\.claude\skills\local-ci-go\scripts\check_prerequisites.ps1
```

### 3. Install Tools

If tools are missing, run:
```powershell
.\.claude\skills\local-ci-go\scripts\install_tools.ps1
```

**Note**: The installer will:
- Install `gosec` via `go install` (requires Go)
- Download and install `gitleaks` to a user directory
- Add gitleaks to your PATH automatically
- You may need to restart PowerShell after installation

### 4. Run CI Checks

```powershell
# Run all checks
.\.claude\skills\local-ci-go\scripts\run_all_checks.ps1

# Or run individual checks
.\.claude\skills\local-ci-go\scripts\run_tests.ps1
.\.claude\skills\local-ci-go\scripts\run_security.ps1
.\.claude\skills\local-ci-go\scripts\run_gitleaks.ps1
```

## PowerShell Script Details

### check_prerequisites.ps1

Verifies that all required tools are installed:
- Go
- gosec
- gitleaks
- git repository status
- go.mod file
- test files

**Exit Code**: 0 if all required tools present, 1 if tools missing

### install_tools.ps1

Automatically installs missing CI tools:
- **gosec**: Installed via `go install` to `$GOPATH/bin`
- **gitleaks**: Downloaded from GitHub releases, installed to:
  - `$env:LOCALAPPDATA\Programs\gitleaks` (preferred)
  - `$env:USERPROFILE\bin` (fallback)
  - `$env:ProgramFiles\gitleaks` (requires admin)

Installation directory is automatically added to user PATH.

**Note**: You may need to restart PowerShell/Terminal for PATH changes to take effect.

### run_tests.ps1

Runs unit tests with coverage validation:
- Baseline: 10% overall coverage
- Incremental: 80% coverage for changed files
- Generates `coverage.out` file

**Usage**:
```powershell
.\.claude\skills\local-ci-go\scripts\run_tests.ps1
```

### run_security.ps1

Runs gosec security scanner:
- Detects SQL injection, weak crypto, hardcoded credentials, etc.
- Uses custom config if `.gosec.json` exists
- Generates detailed security report

**Usage**:
```powershell
.\.claude\skills\local-ci-go\scripts\run_security.ps1
```

### run_gitleaks.ps1

Scans for secrets and sensitive information:
- Default: scans staged changes
- Supports multiple scan modes
- Uses custom config if `.gitleaks.toml` exists

**Usage**:
```powershell
# Scan staged changes (default)
.\.claude\skills\local-ci-go\scripts\run_gitleaks.ps1

# Scan uncommitted changes
.\.claude\skills\local-ci-go\scripts\run_gitleaks.ps1 -ScanMode uncommitted

# Scan entire git history
.\.claude\skills\local-ci-go\scripts\run_gitleaks.ps1 -ScanMode history
```

### run_all_checks.ps1

Runs all CI checks in sequence:
1. Prerequisites check
2. Unit test coverage
3. Security scan (gosec)
4. Secret detection (gitleaks)

Displays summary of passed/failed checks.

**Usage**:
```powershell
.\.claude\skills\local-ci-go\scripts\run_all_checks.ps1
```

## Troubleshooting

### "Execution Policy" Error

If you see an error about execution policy:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

This allows running local PowerShell scripts while maintaining security for downloaded scripts.

### Gitleaks Not Found After Installation

1. **Restart PowerShell/Terminal**:
   - Close and reopen your PowerShell window
   - The PATH update requires a new session

2. **Verify Installation**:
   ```powershell
   # Check if gitleaks is in PATH
   Get-Command gitleaks

   # If not found, check installation directory
   Test-Path "$env:LOCALAPPDATA\Programs\gitleaks\gitleaks.exe"
   ```

3. **Manual PATH Update** (if needed):
   ```powershell
   # Add to current session
   $env:PATH += ";$env:LOCALAPPDATA\Programs\gitleaks"

   # Add permanently for user
   [Environment]::SetEnvironmentVariable(
       "PATH",
       "$env:PATH;$env:LOCALAPPDATA\Programs\gitleaks",
       "User"
   )
   ```

### Go Not in PATH

After installing Go, ensure it's in your PATH:

```powershell
# Check Go installation
go version

# If not found, add Go to PATH (adjust path if different)
[Environment]::SetEnvironmentVariable(
    "PATH",
    "$env:PATH;C:\Program Files\Go\bin",
    "User"
)
```

Then restart PowerShell.

### GOPATH/bin Not in PATH

Go tools like `gosec` are installed to `$GOPATH\bin`. Ensure it's in PATH:

```powershell
# Check current GOPATH
go env GOPATH

# Add GOPATH\bin to PATH
$gopath = go env GOPATH
[Environment]::SetEnvironmentVariable(
    "PATH",
    "$env:PATH;$gopath\bin",
    "User"
)
```

Restart PowerShell after updating PATH.

### Permission Denied

If you see "Access Denied" errors when installing gitleaks:

1. The installer will try multiple locations automatically
2. It should succeed with user-level directories
3. If all fail, download gitleaks manually:
   - Visit: https://github.com/gitleaks/gitleaks/releases
   - Download `gitleaks_X.X.X_windows_x64.zip`
   - Extract `gitleaks.exe` to a directory in your PATH

### Coverage Check Fails with "bc: command not found"

The PowerShell scripts don't use `bc` - they use PowerShell's native arithmetic. If you see this error, you're likely running a bash script instead of the PowerShell version.

Ensure you're running `.ps1` files in PowerShell, not `.sh` files.

## Differences from Linux/macOS

### Path Separators
- **Windows**: Use backslash `\` in paths
- **Unix**: Uses forward slash `/`

PowerShell handles both, but prefer backslash for Windows paths.

### Script Extensions
- **Windows**: Use `.ps1` (PowerShell) scripts
- **Unix**: Use `.sh` (Bash) scripts

### Installation Locations
- **Windows**: Tools install to user directories (`$env:LOCALAPPDATA`, `$env:USERPROFILE`)
- **Unix**: Tools install to `/usr/local/bin` (requires sudo)

### Line Endings
Git on Windows handles line endings automatically (CRLF ↔ LF conversion).

## Advanced Configuration

### Custom Gitleaks Install Location

To install gitleaks to a specific directory:

```powershell
# Download gitleaks manually
$url = "https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_windows_x64.zip"
$tempZip = "$env:TEMP\gitleaks.zip"
Invoke-WebRequest -Uri $url -OutFile $tempZip

# Extract to custom location
$installDir = "C:\Tools\gitleaks"
New-Item -ItemType Directory -Path $installDir -Force
Expand-Archive -Path $tempZip -DestinationPath $installDir -Force

# Add to PATH
[Environment]::SetEnvironmentVariable(
    "PATH",
    "$env:PATH;$installDir",
    "User"
)

Remove-Item $tempZip
```

### Running from Batch File

Create `run-ci.bat`:
```batch
@echo off
powershell.exe -ExecutionPolicy Bypass -File ".\.claude\skills\local-ci-go\scripts\run_all_checks.ps1"
pause
```

Double-click to run CI checks.

### Git Bash Users

If you prefer Git Bash, use the `.sh` scripts instead:
```bash
bash .claude/skills/local-ci-go/scripts/run_all_checks.sh
```

## Support

For issues specific to Windows:
1. Check this guide's Troubleshooting section
2. Verify PowerShell version: `$PSVersionTable.PSVersion`
3. Check Go version: `go version`
4. Verify tools are in PATH: `Get-Command gosec`, `Get-Command gitleaks`

For general local-ci-go issues, see the main [README.md](README.md).
