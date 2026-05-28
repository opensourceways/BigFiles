#!/bin/bash
# Fixer Agent: Automatically fixes security issues based on gosec report
# Uses Claude Code's Task tool to spawn a fixing subagent

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

echo "🔧 Fixer Agent: Analyzing security issues..."

# Count issues
ISSUE_COUNT=$(jq '.Issues | length' "$GOSEC_REPORT" 2>/dev/null || echo "0")

if [ "$ISSUE_COUNT" = "0" ]; then
    echo "No issues to fix"
    echo "# No Issues Found" > "$OUTPUT_FIXES"
    echo "" >> "$OUTPUT_FIXES"
    echo "All security checks passed." >> "$OUTPUT_FIXES"
    exit 0
fi

echo "Found $ISSUE_COUNT issue(s) to fix"

# Initialize fixes document
cat > "$OUTPUT_FIXES" << EOF
# Security Fixes Applied

**Timestamp:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Issues Processed:** $ISSUE_COUNT

## Fixes

EOF

# Process each issue
FIXED_COUNT=0
SKIPPED_COUNT=0

jq -c '.Issues[]' "$GOSEC_REPORT" 2>/dev/null | while IFS= read -r issue; do
    RULE_ID=$(echo "$issue" | jq -r '.RuleID')
    FILE=$(echo "$issue" | jq -r '.File')
    LINE=$(echo "$issue" | jq -r '.Line')
    WHAT=$(echo "$issue" | jq -r '.What')
    CODE=$(echo "$issue" | jq -r '.Code')

    echo ""
    echo "Processing: $RULE_ID in $FILE:$LINE"

    # Apply fix based on rule ID
    case "$RULE_ID" in
        G104)
            # Unhandled errors
            echo "Fixing G104: Unhandled error at $FILE:$LINE"
            if fix_g104 "$FILE" "$LINE" "$CODE"; then
                cat >> "$OUTPUT_FIXES" << EOFFIX
### ✅ Fixed: G104 - Unhandled Error

**File:** \`$FILE:$LINE\`
**Issue:** $WHAT

**Original:**
\`\`\`go
$CODE
\`\`\`

**Fix:** Added error handling

---

EOFFIX
                FIXED_COUNT=$((FIXED_COUNT + 1))
            else
                SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
            fi
            ;;

        G101)
            # Hardcoded credentials
            echo "Fixing G101: Hardcoded credentials at $FILE:$LINE"
            if fix_g101 "$FILE" "$LINE" "$CODE"; then
                cat >> "$OUTPUT_FIXES" << EOFFIX
### ✅ Fixed: G101 - Hardcoded Credentials

**File:** \`$FILE:$LINE\`
**Issue:** $WHAT

**Original:**
\`\`\`go
$CODE
\`\`\`

**Fix:** Replaced with environment variable

---

EOFFIX
                FIXED_COUNT=$((FIXED_COUNT + 1))
            else
                SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
            fi
            ;;

        G401|G501|G505)
            # Weak cryptography
            echo "Fixing $RULE_ID: Weak cryptography at $FILE:$LINE"
            if fix_weak_crypto "$FILE" "$LINE" "$CODE" "$RULE_ID"; then
                cat >> "$OUTPUT_FIXES" << EOFFIX
### ✅ Fixed: $RULE_ID - Weak Cryptography

**File:** \`$FILE:$LINE\`
**Issue:** $WHAT

**Original:**
\`\`\`go
$CODE
\`\`\`

**Fix:** Upgraded to stronger algorithm

---

EOFFIX
                FIXED_COUNT=$((FIXED_COUNT + 1))
            else
                SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
            fi
            ;;

        G201|G202)
            # SQL injection
            echo "Fixing $RULE_ID: SQL injection risk at $FILE:$LINE"
            cat >> "$OUTPUT_FIXES" << EOFFIX
### ⚠️ Skipped: $RULE_ID - SQL Injection

**File:** \`$FILE:$LINE\`
**Issue:** $WHAT

**Reason:** Requires manual review - SQL query context needed

**Recommendation:** Use parameterized queries

---

EOFFIX
            SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
            ;;

        G304)
            # File path traversal
            echo "Fixing G304: Path traversal at $FILE:$LINE"
            if fix_g304 "$FILE" "$LINE" "$CODE"; then
                cat >> "$OUTPUT_FIXES" << EOFFIX
### ✅ Fixed: G304 - Path Traversal

**File:** \`$FILE:$LINE\`
**Issue:** $WHAT

**Original:**
\`\`\`go
$CODE
\`\`\`

**Fix:** Added path validation

---

EOFFIX
                FIXED_COUNT=$((FIXED_COUNT + 1))
            else
                SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
            fi
            ;;

        *)
            echo "Skipping $RULE_ID: No auto-fix available"
            cat >> "$OUTPUT_FIXES" << EOFFIX
### ⚠️ Skipped: $RULE_ID

**File:** \`$FILE:$LINE\`
**Issue:** $WHAT

**Reason:** No automatic fix available

---

EOFFIX
            SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
            ;;
    esac
done

# Add summary
cat >> "$OUTPUT_FIXES" << EOF

## Summary

- **Fixed:** $FIXED_COUNT
- **Skipped:** $SKIPPED_COUNT
- **Total:** $ISSUE_COUNT

EOF

echo ""
echo "Fixer Agent completed:"
echo "  Fixed: $FIXED_COUNT"
echo "  Skipped: $SKIPPED_COUNT"
echo ""

# Exit with success if at least some fixes were applied
[ "$FIXED_COUNT" -gt 0 ] && exit 0 || exit 1

# Fix functions

fix_g104() {
    local file="$1"
    local line="$2"
    local code="$3"

    # Check if this is a defer statement (common pattern)
    if echo "$code" | grep -q "defer"; then
        # Add error check for defer
        # This is a simplified example - real implementation would need AST parsing
        return 1  # Skip for now - needs manual review
    fi

    # For other cases, try to add error handling
    # This is a placeholder - actual implementation would use go/ast
    return 1
}

fix_g101() {
    local file="$1"
    local line="$2"
    local code="$3"

    # Extract variable name and value
    # This is a placeholder - actual implementation would parse the code
    # and replace hardcoded values with os.Getenv calls
    return 1
}

fix_weak_crypto() {
    local file="$1"
    local line="$2"
    local code="$3"
    local rule="$4"

    # Replace weak crypto with strong alternatives
    # md5 -> sha256, sha1 -> sha256, des -> aes
    # This is a placeholder
    return 1
}

fix_g304() {
    local file="$1"
    local line="$2"
    local code="$3"

    # Add filepath.Clean() call
    # This is a placeholder
    return 1
}
