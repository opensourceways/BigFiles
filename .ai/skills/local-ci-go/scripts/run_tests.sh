#!/bin/bash
# Run unit tests with coverage validation
# Checks: 10% baseline coverage, 80% incremental coverage for changed code

set -e

echo "🧪 Running unit tests with coverage validation..."
echo ""

# Configuration
BASELINE_COVERAGE=10    # Minimum overall coverage (%)
INCREMENTAL_COVERAGE=80 # Minimum coverage for changed code (%)

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed"
    exit 1
fi

# Check if go.mod exists
if [ ! -f go.mod ]; then
    echo "❌ go.mod not found. Is this a Go module?"
    exit 1
fi

# Run tests with coverage
echo "Running tests..."
if ! go test -coverprofile=coverage.out ./... 2>&1 | tee test_output.txt; then
    echo ""
    echo "❌ Tests failed!"
    echo ""
    echo "To debug:"
    echo "  - Check test_output.txt for details"
    echo "  - Run specific test: go test -v -run TestName ./..."
    rm -f test_output.txt
    exit 1
fi

echo ""

# Check if coverage file was generated
if [ ! -f coverage.out ]; then
    echo "❌ coverage.out not generated"
    exit 1
fi

# Calculate overall coverage
echo "📊 Analyzing coverage..."
total_coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')

if [ -z "$total_coverage" ]; then
    echo "❌ Failed to calculate coverage"
    exit 1
fi

echo "Overall coverage: ${total_coverage}%"

# Check baseline coverage
if (( $(echo "$total_coverage < $BASELINE_COVERAGE" | bc -l) )); then
    echo "❌ Coverage ${total_coverage}% is below baseline ${BASELINE_COVERAGE}%"
    echo ""
    echo "To improve coverage:"
    echo "  1. View coverage report: go tool cover -html=coverage.out"
    echo "  2. Identify uncovered code: go tool cover -func=coverage.out | grep -v '100.0%'"
    echo "  3. Add tests for uncovered functions"
    exit 1
fi

echo "✅ Baseline coverage check passed (${total_coverage}% >= ${BASELINE_COVERAGE}%)"
echo ""

# Check incremental coverage (for changed files)
if git rev-parse --git-dir > /dev/null 2>&1; then
    echo "📈 Checking incremental coverage for changed files..."

    # Get list of changed Go files (excluding test files)
    changed_files=$(git diff --name-only --diff-filter=ACM HEAD | grep '\.go$' | grep -v '_test\.go$' || true)

    if [ -z "$changed_files" ]; then
        echo "ℹ️  No changed Go files found (excluding tests)"
        echo "✅ Incremental coverage check skipped"
    else
        echo "Changed files:"
        echo "$changed_files" | sed 's/^/  - /'
        echo ""

        # Extract coverage for changed files
        failed_files=()

        while IFS= read -r file; do
            if [ -f "$file" ]; then
                # Get coverage for this file
                file_coverage=$(go tool cover -func=coverage.out | grep "^$file:" | awk '{sum+=$3; count++} END {if(count>0) print sum/count; else print 0}' | sed 's/%//')

                if [ -z "$file_coverage" ] || [ "$file_coverage" = "0" ]; then
                    echo "  ⚠️  $file: no coverage data"
                    failed_files+=("$file (no coverage)")
                elif (( $(echo "$file_coverage < $INCREMENTAL_COVERAGE" | bc -l) )); then
                    echo "  ❌ $file: ${file_coverage}% (< ${INCREMENTAL_COVERAGE}%)"
                    failed_files+=("$file (${file_coverage}%)")
                else
                    echo "  ✅ $file: ${file_coverage}%"
                fi
            fi
        done <<< "$changed_files"

        echo ""

        if [ ${#failed_files[@]} -gt 0 ]; then
            echo "❌ Incremental coverage check failed for ${#failed_files[@]} file(s):"
            for file in "${failed_files[@]}"; do
                echo "  - $file"
            done
            echo ""
            echo "To improve incremental coverage:"
            echo "  1. View coverage: go tool cover -html=coverage.out"
            echo "  2. Focus on changed files listed above"
            echo "  3. Add tests to reach ${INCREMENTAL_COVERAGE}% coverage"
            exit 1
        fi

        echo "✅ Incremental coverage check passed (all changed files >= ${INCREMENTAL_COVERAGE}%)"
    fi
else
    echo "ℹ️  Not a git repository - skipping incremental coverage check"
fi

echo ""

# Generate coverage report
echo "📄 Coverage report:"
go tool cover -func=coverage.out | tail -20

echo ""
echo "✅ All coverage checks passed!"
echo ""
echo "View detailed coverage:"
echo "  go tool cover -html=coverage.out"

# Cleanup
rm -f test_output.txt
