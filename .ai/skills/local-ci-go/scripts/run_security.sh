#!/bin/bash
# Run gosec security scanner to detect vulnerabilities

set -e

# Parse arguments
JSON_OUTPUT=""
QUIET=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --json-output)
            JSON_OUTPUT="$2"
            shift 2
            ;;
        --quiet)
            QUIET=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [ "$QUIET" = false ]; then
    echo "🔒 Running security scan with gosec..."
    echo ""
fi

# Check if gosec is installed
if ! command -v gosec &> /dev/null; then
    echo "❌ gosec is not installed"
    echo ""
    echo "Install with:"
    echo "  go install github.com/securego/gosec/v2/cmd/gosec@latest"
    echo ""
    echo "Or run:"
    echo "  bash .claude/skills/local-ci-go/scripts/install_tools.sh"
    exit 1
fi

# Check if go.mod exists
if [ ! -f go.mod ]; then
    echo "❌ go.mod not found. Is this a Go module?"
    exit 1
fi

# Check for custom gosec configuration
if [ -f .gosec.json ]; then
    [ "$QUIET" = false ] && echo "Using custom configuration: .gosec.json"
    CONFIG_ARG="-conf .gosec.json"
else
    [ "$QUIET" = false ] && echo "Using default gosec configuration"
    CONFIG_ARG=""
fi

[ "$QUIET" = false ] && echo ""

# Determine output format
if [ -n "$JSON_OUTPUT" ]; then
    # JSON output mode
    [ "$QUIET" = false ] && echo "Scanning for security vulnerabilities (JSON output)..."

    # Create parent directory if needed
    JSON_DIR=$(dirname "$JSON_OUTPUT")
    mkdir -p "$JSON_DIR"

    if gosec $CONFIG_ARG -fmt=json -out="$JSON_OUTPUT" ./... 2>&1 | grep -v "Results written to"; then
        [ "$QUIET" = false ] && echo ""
        [ "$QUIET" = false ] && echo "✅ No security issues found!"
        [ "$QUIET" = false ] && echo "JSON report: $JSON_OUTPUT"
        exit 0
    else
        EXIT_CODE=$?

        # Ensure JSON file exists even on error
        if [ ! -f "$JSON_OUTPUT" ]; then
            echo '{"Golang errors": {}, "Issues": [], "Stats": {"files": 0, "lines": 0, "nosec": 0, "found": 0}}' > "$JSON_OUTPUT"
        fi

        [ "$QUIET" = false ] && echo ""
        [ "$QUIET" = false ] && echo "❌ Security issues detected!"
        [ "$QUIET" = false ] && echo "JSON report: $JSON_OUTPUT"

        # Parse issue count from JSON
        ISSUE_COUNT=$(jq '.Stats.found // 0' "$JSON_OUTPUT" 2>/dev/null || echo "0")
        [ "$QUIET" = false ] && echo "Found $ISSUE_COUNT issue(s)"

        exit $EXIT_CODE
    fi
else
    # Text output mode (original behavior)
    [ "$QUIET" = false ] && echo "Scanning for security vulnerabilities..."

    if gosec $CONFIG_ARG -fmt=text ./... 2>&1 | tee gosec_output.txt; then
        echo ""
        echo "✅ No security issues found!"
        rm -f gosec_output.txt
        exit 0
    else
        EXIT_CODE=$?
        echo ""
        echo "❌ Security issues detected!"
        echo ""
        echo "Common fixes:"
        echo ""
        echo "G101 - Hardcoded credentials:"
        echo "  Use environment variables: apiKey := os.Getenv(\"API_KEY\")"
        echo ""
        echo "G104 - Unhandled errors:"
        echo "  Always check errors: if err := file.Close(); err != nil { ... }"
        echo ""
        echo "G201/G202 - SQL injection:"
        echo "  Use parameterized queries: db.Query(\"SELECT * FROM users WHERE id = ?\", userId)"
        echo ""
        echo "G304 - File path traversal:"
        echo "  Validate paths: cleanPath := filepath.Clean(userInput)"
        echo ""
        echo "G401-G406 - Weak cryptography:"
        echo "  Use strong algorithms: sha256.New() instead of md5.New()"
        echo ""
        echo "For detailed fixes, see:"
        echo "  .claude/skills/local-ci-go/references/security-best-practices.md"
        echo ""
        echo "To exclude specific issues (use sparingly):"
        echo "  Add #nosec comment: password := \"temp\" // #nosec G101"
        echo "  Or configure .gosec.json to exclude rule globally"
        echo ""
        echo "💡 Tip: Run with --auto-fix to attempt automatic fixes:"
        echo "  bash .claude/skills/local-ci-go/scripts/security-fix/orchestrator.sh --auto-fix"
        echo ""

        rm -f gosec_output.txt
        exit $EXIT_CODE
    fi
fi
