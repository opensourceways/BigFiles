#!/bin/bash
# Run all CI checks in sequence

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=================================="
echo "🚀 Running all CI checks for Go"
echo "=================================="
echo ""

# Check prerequisites first
echo "Step 1: Checking prerequisites..."
echo ""

if ! bash "$SCRIPT_DIR/check_prerequisites.sh"; then
    echo ""
    echo "❌ Prerequisites check failed!"
    echo ""
    echo "Please install missing tools first:"
    echo "  bash .claude/skills/local-ci-go/scripts/install_tools.sh"
    echo ""
    exit 1
fi

echo ""
echo "Step 2: Running CI checks..."
echo ""

# Track failures
FAILED_CHECKS=()
PASSED_CHECKS=()

# Function to run a check
run_check() {
    local check_name=$1
    local script_name=$2

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "▶️  Running: $check_name"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if bash "$SCRIPT_DIR/$script_name"; then
        PASSED_CHECKS+=("$check_name")
        echo ""
    else
        FAILED_CHECKS+=("$check_name")
        echo "❌ $check_name failed!"
        echo ""
    fi
}

# Run all checks
run_check "Unit Test Coverage" "run_tests.sh"
run_check "Security Scan (Gosec)" "run_security.sh"
run_check "Secret Detection (Gitleaks)" "run_gitleaks.sh"

# Summary
echo "=================================="
echo "📊 CI Checks Summary"
echo "=================================="
echo ""

if [ ${#PASSED_CHECKS[@]} -gt 0 ]; then
    echo "✅ Passed (${#PASSED_CHECKS[@]}):"
    for check in "${PASSED_CHECKS[@]}"; do
        echo "   - $check"
    done
    echo ""
fi

if [ ${#FAILED_CHECKS[@]} -gt 0 ]; then
    echo "❌ Failed (${#FAILED_CHECKS[@]}):"
    for check in "${FAILED_CHECKS[@]}"; do
        echo "   - $check"
    done
    echo ""
    echo "Run individual checks to see detailed error messages:"
    for check in "${FAILED_CHECKS[@]}"; do
        case "$check" in
            "Unit Test Coverage")
                echo "   bash .claude/skills/local-ci-go/scripts/run_tests.sh"
                ;;
            "Security Scan (Gosec)")
                echo "   bash .claude/skills/local-ci-go/scripts/run_security.sh"
                ;;
            "Secret Detection (Gitleaks)")
                echo "   bash .claude/skills/local-ci-go/scripts/run_gitleaks.sh"
                ;;
        esac
    done
    echo ""
    exit 1
fi

echo "🎉 All CI checks passed!"
echo ""
echo "Your code is ready to commit and push!"
