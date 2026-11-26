#!/bin/bash
# Smart Fixer Agent using Claude Code
# Dispatches fixing tasks to Claude Code agent for intelligent code analysis and fixes

set -e

GOSEC_REPORT="$1"
OUTPUT_FIXES="$2"

if [ -z "$GOSEC_REPORT" ] || [ -z "$OUTPUT_FIXES" ]; then
    echo "Usage: $0 <gosec-report.json> <output-fixes.md>"
    exit 1
fi

if [ ! -f "$GOSEC_REPORT" ]; then
    echo "Error: $GOSEC_REPORT not found"
    exit 1
fi

echo "🤖 Smart Fixer Agent: Using Claude Code for intelligent fixes..."

# Check if Claude Code CLI is available
if ! command -v claude &> /dev/null; then
    echo "⚠️  Claude Code CLI not found. Falling back to basic fixes."
    exec "$(dirname "$0")/fixer_agent.sh" "$GOSEC_REPORT" "$OUTPUT_FIXES"
    exit $?
fi

# Count issues
ISSUE_COUNT=$(jq '.Issues | length' "$GOSEC_REPORT" 2>/dev/null || echo "0")

if [ "$ISSUE_COUNT" = "0" ]; then
    echo "No issues to fix"
    echo "# No Issues Found" > "$OUTPUT_FIXES"
    echo "" >> "$OUTPUT_FIXES"
    echo "All security checks passed." >> "$OUTPUT_FIXES"
    exit 0
fi

echo "Found $ISSUE_COUNT issue(s) to fix with AI assistance"
echo ""

# Generate fixing prompt from gosec report
PROMPT_FILE=".ci-temp/fix-prompt.txt"

cat > "$PROMPT_FILE" << 'EOF'
# Security Fix Task

I need you to fix security issues found by gosec in this Go project.

## Gosec Report

EOF

cat "$GOSEC_REPORT" >> "$PROMPT_FILE"

cat >> "$PROMPT_FILE" << 'EOF'

## Instructions

Please analyze each security issue and apply appropriate fixes:

1. **For each issue**, identify the security vulnerability
2. **Apply the fix** using Go best practices
3. **Document what you changed** in a clear, structured format
4. **Verify the fix** doesn't break existing functionality

### Fix Guidelines

- **G101 (Hardcoded credentials)**: Replace with `os.Getenv()` or configuration
- **G104 (Unhandled errors)**: Add proper error handling
- **G201/G202 (SQL injection)**: Use parameterized queries
- **G304 (File traversal)**: Add `filepath.Clean()` and validation
- **G401-G406 (Weak crypto)**: Upgrade to SHA256 or stronger

### Output Format

Create a markdown file with:
- Summary of fixes applied
- Detailed list of changes (file, line, before/after)
- Any issues that couldn't be auto-fixed
- Recommendations for manual review

Save your detailed fix report to: EOF

echo "$OUTPUT_FIXES" >> "$PROMPT_FILE"

cat >> "$PROMPT_FILE" << 'EOF'

## Important Notes

- Make sure all fixes are syntactically correct Go code
- Run `go fmt` on modified files
- Don't introduce new issues while fixing others
- Preserve existing code structure and style where possible
- If unsure about a fix, document it for manual review

Start fixing now!
EOF

# Dispatch to Claude Code agent
echo "Dispatching to Claude Code agent for fixes..."
echo ""

if claude --prompt-file "$PROMPT_FILE" --output "$OUTPUT_FIXES.log" 2>&1 | tee "$OUTPUT_FIXES.agent.log"; then
    echo ""
    echo "✅ Claude Code agent completed successfully"

    # Check if output file was created
    if [ -f "$OUTPUT_FIXES" ]; then
        echo "✓ Fix report generated: $OUTPUT_FIXES"
        exit 0
    else
        echo "⚠️  Output file not generated, creating summary from log"
        # Extract summary from agent log
        cp "$OUTPUT_FIXES.agent.log" "$OUTPUT_FIXES"
        exit 0
    fi
else
    EXIT_CODE=$?
    echo ""
    echo "⚠️  Claude Code agent encountered issues (exit code: $EXIT_CODE)"
    echo "Falling back to basic fixes..."

    # Fallback to basic fixer
    exec "$(dirname "$0")/fixer_agent.sh" "$GOSEC_REPORT" "$OUTPUT_FIXES"
fi
