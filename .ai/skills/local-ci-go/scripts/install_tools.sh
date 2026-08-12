#!/bin/bash
# Install all required tools for CI checks

set -e

echo "📥 Installing CI tools for Go projects..."
echo ""

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

echo "Detected: $OS $ARCH"
echo ""

# Install gosec
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Installing gosec..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v go &> /dev/null; then
    go install github.com/securego/gosec/v2/cmd/gosec@latest
    echo "✅ gosec installed"
else
    echo "❌ Go is not installed. Please install Go first: https://go.dev/doc/install"
    exit 1
fi

echo ""

# Install gitleaks
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Installing gitleaks..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v gitleaks &> /dev/null; then
    echo "✅ gitleaks already installed: $(gitleaks version)"
else
    # Determine download URL based on OS and architecture
    GITLEAKS_VERSION="8.18.2"

    case "$OS" in
        Linux)
            case "$ARCH" in
                x86_64)
                    GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
                    ;;
                aarch64|arm64)
                    GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz"
                    ;;
                *)
                    echo "❌ Unsupported architecture: $ARCH"
                    exit 1
                    ;;
            esac
            ;;
        Darwin)
            case "$ARCH" in
                x86_64)
                    GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_darwin_x64.tar.gz"
                    ;;
                arm64)
                    GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_darwin_arm64.tar.gz"
                    ;;
                *)
                    echo "❌ Unsupported architecture: $ARCH"
                    exit 1
                    ;;
            esac
            ;;
        *)
            echo "❌ Unsupported OS: $OS"
            echo "Please install gitleaks manually: https://github.com/gitleaks/gitleaks#installing"
            exit 1
            ;;
    esac

    # Download and install
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"

    echo "Downloading gitleaks from $GITLEAKS_URL..."
    curl -sSL "$GITLEAKS_URL" -o gitleaks.tar.gz

    echo "Extracting..."
    tar -xzf gitleaks.tar.gz

    echo "Installing to /usr/local/bin (may require sudo)..."
    if [ -w /usr/local/bin ]; then
        mv gitleaks /usr/local/bin/
    else
        sudo mv gitleaks /usr/local/bin/
    fi

    cd - > /dev/null
    rm -rf "$TEMP_DIR"

    echo "✅ gitleaks installed: $(gitleaks version)"
fi

echo ""

# Install optional tools
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Installing optional tools..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v go-test-coverage &> /dev/null; then
    echo "✅ go-test-coverage already installed"
else
    echo "Installing go-test-coverage..."
    go install github.com/vladopajic/go-test-coverage/v2@latest
    echo "✅ go-test-coverage installed"
fi

echo ""

# Verify installations
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Verifying installations..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

ALL_OK=true

if command -v gosec &> /dev/null; then
    echo "✅ gosec: $(gosec --version 2>&1 | head -1)"
else
    echo "❌ gosec: not found"
    ALL_OK=false
fi

if command -v gitleaks &> /dev/null; then
    echo "✅ gitleaks: $(gitleaks version 2>&1)"
else
    echo "❌ gitleaks: not found"
    ALL_OK=false
fi

if command -v go-test-coverage &> /dev/null; then
    echo "✅ go-test-coverage: installed"
else
    echo "⚠️  go-test-coverage: not found (optional)"
fi

echo ""

if [ "$ALL_OK" = true ]; then
    echo "🎉 All tools installed successfully!"
    echo ""
    echo "You can now run CI checks:"
    echo "  bash .claude/skills/local-ci-go/scripts/run_all_checks.sh"
else
    echo "❌ Some tools failed to install"
    echo "Please install them manually or check the error messages above"
    exit 1
fi
