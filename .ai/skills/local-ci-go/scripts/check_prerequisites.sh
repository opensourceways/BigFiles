#!/bin/bash
# Check all prerequisites for CI checks before running

echo "🔍 Checking prerequisites for local CI checks..."
echo ""

MISSING_TOOLS=()
ALL_OK=true

# Check for required tools
echo "📦 Checking installed tools:"

if command -v go &> /dev/null; then
    echo "  ✅ go: $(go version)"
else
    echo "  ❌ go: not installed"
    MISSING_TOOLS+=("go")
    ALL_OK=false
fi

if command -v gosec &> /dev/null; then
    echo "  ✅ gosec: $(gosec --version 2>&1 | head -1)"
else
    echo "  ❌ gosec: not installed"
    MISSING_TOOLS+=("gosec")
    ALL_OK=false
fi

if command -v gitleaks &> /dev/null; then
    echo "  ✅ gitleaks: $(gitleaks version 2>&1)"
else
    echo "  ❌ gitleaks: not installed"
    MISSING_TOOLS+=("gitleaks")
    ALL_OK=false
fi

echo ""

# Check for optional tools
echo "📦 Checking optional tools:"

if command -v go-test-coverage &> /dev/null; then
    echo "  ✅ go-test-coverage: installed"
else
    echo "  ⚠️  go-test-coverage: not installed (optional, for better coverage reports)"
fi

echo ""

# Check for git repository
echo "📁 Checking project setup:"

if git rev-parse --git-dir > /dev/null 2>&1; then
    echo "  ✅ git repository: initialized"
else
    echo "  ⚠️  git repository: not initialized (needed for incremental coverage)"
    echo "     Run: git init"
fi

# Check for Go module
if [ -f go.mod ]; then
    echo "  ✅ go.mod: found"
else
    echo "  ⚠️  go.mod: not found"
    echo "     Run: go mod init <module-name>"
fi

# Check for test files
if find . -name "*_test.go" -type f | grep -q .; then
    test_count=$(find . -name "*_test.go" -type f | wc -l)
    echo "  ✅ test files: found ($test_count files)"
else
    echo "  ⚠️  test files: no *_test.go files found"
fi

echo ""

# Summary and recommendations
if [ "$ALL_OK" = true ]; then
    echo "🎉 All required tools are installed!"
    echo ""
    echo "You can now run CI checks:"
    echo "  bash .claude/skills/local-ci-go/scripts/run_all_checks.sh"
    echo ""
    exit 0
else
    echo "❌ Some required tools are missing!"
    echo ""

    if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
        echo "📥 Missing tools that need to be installed:"
        for tool in "${MISSING_TOOLS[@]}"; do
            echo "  - $tool"
        done
        echo ""
        echo "To install all missing tools, run:"
        echo "  bash .claude/skills/local-ci-go/scripts/install_tools.sh"
        echo ""
        echo "Or install individually:"
        for tool in "${MISSING_TOOLS[@]}"; do
            case "$tool" in
                "go")
                    echo "  - go: https://go.dev/doc/install"
                    ;;
                "gosec")
                    echo "  - gosec: go install github.com/securego/gosec/v2/cmd/gosec@latest"
                    ;;
                "gitleaks")
                    echo "  - gitleaks: https://github.com/gitleaks/gitleaks#installing"
                    ;;
            esac
        done
        echo ""
    fi

    exit 1
fi
