#!/bin/bash
# Verifier Agent: Verifies that security fixes were applied correctly
# Re-runs gosec and compares results

set -e

ORIGINAL_REPORT="$1"
FIXES_APPLIED="$2"
VERIFICATION_OUTPUT="$3"

if [ -z "$ORIGINAL_REPORT" ] || [ -z "$FIXES_APPLIED" ] || [ -z "$VERIFICATION_OUTPUT" ]; then
    echo "Usage: $0 <original-report.json> <fixes-applied.md> <verification-output.md>"
    exit 1
fi

echo "🔍 Verifier Agent: Re-scanning for security issues..."

# Run gosec again
TEMP_REPORT=".ci-temp/gosec-reverify.json"
mkdir -p .ci-temp

# Run security scan again
if bash "$(dirname "$0")/../run_security.sh" --json-output "$TEMP_REPORT" 2>/dev/null; then
    # No issues found - complete success!
    STATUS="PASS"
    ORIGINAL_COUNT=$(jq '.Issues | length' "$ORIGINAL_REPORT" 2>/dev/null || echo "0")
    NEW_COUNT=0
    FIXED_COUNT=$ORIGINAL_COUNT
else
    # Still have issues - compare counts
    ORIGINAL_COUNT=$(jq '.Issues | length' "$ORIGINAL_REPORT" 2>/dev/null || echo "0")
    NEW_COUNT=$(jq '.Issues | length' "$TEMP_REPORT" 2>/dev/null || echo "0")
    FIXED_COUNT=$((ORIGINAL_COUNT - NEW_COUNT))

    if [ "$NEW_COUNT" -eq 0 ]; then
        STATUS="PASS"
    elif [ "$NEW_COUNT" -lt "$ORIGINAL_COUNT" ]; then
        STATUS="PARTIAL"
    else
        STATUS="FAIL"
    fi
fi

# Generate verification report
cat > "$VERIFICATION_OUTPUT" << EOF
# Verification Report

**Timestamp:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Status:** $STATUS

## Results

- **Original Issues:** $ORIGINAL_COUNT
- **Remaining Issues:** $NEW_COUNT
- **Fixed Issues:** $FIXED_COUNT
- **Fix Rate:** $(awk "BEGIN {printf \"%.1f\", ($FIXED_COUNT / $ORIGINAL_COUNT) * 100}")%

EOF

case "$STATUS" in
    PASS)
        cat >> "$VERIFICATION_OUTPUT" << EOF
## ✅ Verification Passed

All security issues have been successfully resolved!

### Summary
- All $ORIGINAL_COUNT issue(s) fixed
- No remaining vulnerabilities
- Code is ready for commit

EOF
        ;;

    PARTIAL)
        cat >> "$VERIFICATION_OUTPUT" << EOF
## ⚠️ Partial Success

Some issues were fixed, but $NEW_COUNT issue(s) remain.

### Progress
- Fixed: $FIXED_COUNT / $ORIGINAL_COUNT issue(s)
- Remaining: $NEW_COUNT issue(s)

### Remaining Issues

EOF

        # List remaining issues
        if [ -f "$TEMP_REPORT" ]; then
            jq -r '.Issues[] | "- **\(.RuleID)** in `\(.File):\(.Line)` - \(.What)"' "$TEMP_REPORT" >> "$VERIFICATION_OUTPUT"
        fi

        cat >> "$VERIFICATION_OUTPUT" << EOF

### Recommendation
- Review remaining issues manually
- Run another fix iteration
- Consult security-best-practices.md

EOF
        ;;

    FAIL)
        cat >> "$VERIFICATION_OUTPUT" << EOF
## ❌ Verification Failed

No progress was made in fixing security issues.

### Analysis
- Original issues: $ORIGINAL_COUNT
- Current issues: $NEW_COUNT
- Fixes may have introduced new issues or were not applied correctly

### Next Steps
1. Review the fixes that were attempted
2. Check for syntax errors or test failures
3. Consider manual intervention
4. Consult with security expert

EOF
        ;;
esac

# Add detailed comparison if there are still issues
if [ "$NEW_COUNT" -gt 0 ] && [ -f "$TEMP_REPORT" ]; then
    cat >> "$VERIFICATION_OUTPUT" << EOF

## Detailed Issue Breakdown

### By Severity

EOF

    HIGH=$(jq '[.Issues[] | select(.Severity == "HIGH")] | length' "$TEMP_REPORT" 2>/dev/null || echo "0")
    MEDIUM=$(jq '[.Issues[] | select(.Severity == "MEDIUM")] | length' "$TEMP_REPORT" 2>/dev/null || echo "0")
    LOW=$(jq '[.Issues[] | select(.Severity == "LOW")] | length' "$TEMP_REPORT" 2>/dev/null || echo "0")

    cat >> "$VERIFICATION_OUTPUT" << EOF
| Severity | Count |
|----------|-------|
| 🔴 HIGH   | $HIGH |
| 🟡 MEDIUM | $MEDIUM |
| 🟢 LOW    | $LOW |

### By Rule

EOF

    jq -r '.Issues | group_by(.RuleID) | .[] | "- \(.| length)x **\(.[0].RuleID)**: \(.[0].What)"' "$TEMP_REPORT" >> "$VERIFICATION_OUTPUT"
fi

echo ""
echo "Verification completed: $STATUS"
echo "  Original: $ORIGINAL_COUNT issues"
echo "  Remaining: $NEW_COUNT issues"
echo "  Fixed: $FIXED_COUNT issues"
echo ""

# Exit codes: 0 = PASS, 1 = PARTIAL/FAIL
[ "$STATUS" = "PASS" ] && exit 0 || exit 1
