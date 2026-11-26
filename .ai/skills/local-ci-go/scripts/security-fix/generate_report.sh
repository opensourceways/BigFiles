#!/bin/bash
# Generate human-readable security report from gosec JSON output

set -e

GOSEC_JSON="$1"
OUTPUT_MD="$2"

if [ -z "$GOSEC_JSON" ] || [ -z "$OUTPUT_MD" ]; then
    echo "Usage: $0 <gosec-report.json> <output.md>"
    exit 1
fi

if [ ! -f "$GOSEC_JSON" ]; then
    echo "Error: $GOSEC_JSON not found"
    exit 1
fi

# Parse JSON and generate markdown
cat > "$OUTPUT_MD" << 'EOF'
# Security Scan Report

**Generated:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")

EOF

# Add summary
ISSUE_COUNT=$(jq '.Issues | length' "$GOSEC_JSON" 2>/dev/null || echo "0")

cat >> "$OUTPUT_MD" << EOF
## Summary

- **Total Issues:** $ISSUE_COUNT
- **Scan Tool:** gosec

EOF

# Group issues by severity
HIGH_COUNT=$(jq '[.Issues[] | select(.Severity == "HIGH")] | length' "$GOSEC_JSON" 2>/dev/null || echo "0")
MEDIUM_COUNT=$(jq '[.Issues[] | select(.Severity == "MEDIUM")] | length' "$GOSEC_JSON" 2>/dev/null || echo "0")
LOW_COUNT=$(jq '[.Issues[] | select(.Severity == "LOW")] | length' "$GOSEC_JSON" 2>/dev/null || echo "0")

cat >> "$OUTPUT_MD" << EOF
### By Severity

| Severity | Count |
|----------|-------|
| 🔴 HIGH   | $HIGH_COUNT |
| 🟡 MEDIUM | $MEDIUM_COUNT |
| 🟢 LOW    | $LOW_COUNT |

EOF

# Group by rule ID
cat >> "$OUTPUT_MD" << EOF
### By Rule

EOF

jq -r '.Issues | group_by(.RuleID) | .[] | "\(.| length)x \(.[0].RuleID): \(.[0].What)"' "$GOSEC_JSON" 2>/dev/null | \
    sort -rn | \
    while read -r line; do
        echo "- $line" >> "$OUTPUT_MD"
    done

cat >> "$OUTPUT_MD" << EOF

## Detailed Issues

EOF

# List all issues with details
jq -r '.Issues[] | "### Issue: \(.What)\n\n**Rule:** `\(.RuleID)`  \n**Severity:** \(.Severity)  \n**Confidence:** \(.Confidence)\n\n**Location:** `\(.File):\(.Line)`\n\n**Code:**\n```go\n\(.Code)\n```\n\n**Details:**\n\(.Details)\n\n---\n"' "$GOSEC_JSON" 2>/dev/null >> "$OUTPUT_MD"

echo "Report generated: $OUTPUT_MD"
