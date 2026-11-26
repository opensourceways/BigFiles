#!/bin/bash
# Security Fix Orchestrator
# Coordinates the security scan, fix, and verification workflow

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEMP_DIR=".ci-temp"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}🛡️  Security Fix Orchestrator${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Create temp directory
mkdir -p "$TEMP_DIR"

# Parse options
AUTO_FIX=false
INTERACTIVE=true
MAX_ITERATIONS=3

while [[ $# -gt 0 ]]; do
    case $1 in
        --auto-fix)
            AUTO_FIX=true
            shift
            ;;
        --no-interactive)
            INTERACTIVE=false
            shift
            ;;
        --max-iterations)
            MAX_ITERATIONS="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Step 1: Run gosec scan and generate report
echo -e "${BLUE}[Step 1/4]${NC} Running security scan..."
echo ""

if ! bash "$SCRIPT_DIR/../run_security.sh" --json-output "$TEMP_DIR/gosec-report.json"; then
    SCAN_EXIT_CODE=$?

    if [ ! -f "$TEMP_DIR/gosec-report.json" ]; then
        echo -e "${RED}❌ Security scan failed and no report was generated${NC}"
        exit 1
    fi

    echo -e "${YELLOW}⚠️  Security issues detected (exit code: $SCAN_EXIT_CODE)${NC}"

    # Parse report to get issue count
    ISSUE_COUNT=$(jq '.Issues | length' "$TEMP_DIR/gosec-report.json" 2>/dev/null || echo "0")
    echo -e "${YELLOW}📊 Found $ISSUE_COUNT security issue(s)${NC}"
    echo ""

    # Generate human-readable summary
    bash "$SCRIPT_DIR/generate_report.sh" "$TEMP_DIR/gosec-report.json" "$TEMP_DIR/security-scan-summary.md"

    echo -e "${GREEN}✓${NC} Report generated: $TEMP_DIR/security-scan-summary.md"
    echo ""

    # Display summary
    if [ -f "$TEMP_DIR/security-scan-summary.md" ]; then
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        head -50 "$TEMP_DIR/security-scan-summary.md"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
    fi

    # Ask user if they want to auto-fix
    if [ "$AUTO_FIX" = false ] && [ "$INTERACTIVE" = true ]; then
        echo -e "${YELLOW}Do you want to attempt automatic fixes? (y/n)${NC}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            echo "Fix cancelled by user"
            exit 1
        fi
        AUTO_FIX=true
    fi

    if [ "$AUTO_FIX" = false ]; then
        echo -e "${YELLOW}⚠️  Auto-fix not enabled. Run with --auto-fix to attempt automatic fixes.${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✅ No security issues found!${NC}"
    exit 0
fi

# Step 2: Attempt fixes with Fixer Agent
echo -e "${BLUE}[Step 2/4]${NC} Attempting automatic fixes..."
echo ""

ITERATION=1
FIX_SUCCESS=false

while [ $ITERATION -le $MAX_ITERATIONS ]; do
    echo -e "${CYAN}🔧 Fix Iteration $ITERATION/$MAX_ITERATIONS${NC}"

    if bash "$SCRIPT_DIR/fixer_agent.sh" "$TEMP_DIR/gosec-report.json" "$TEMP_DIR/security-fixes-iter$ITERATION.md"; then
        echo -e "${GREEN}✓${NC} Fixes applied"

        # Step 3: Verify fixes with Verifier Agent
        echo ""
        echo -e "${BLUE}[Step 3/4]${NC} Verifying fixes..."
        echo ""

        if bash "$SCRIPT_DIR/verifier_agent.sh" "$TEMP_DIR/gosec-report.json" "$TEMP_DIR/security-fixes-iter$ITERATION.md" "$TEMP_DIR/verification-report-iter$ITERATION.md"; then
            VERIFICATION_RESULT=$(grep "^Status:" "$TEMP_DIR/verification-report-iter$ITERATION.md" | awk '{print $2}')

            case "$VERIFICATION_RESULT" in
                PASS)
                    echo -e "${GREEN}✅ All issues fixed and verified!${NC}"
                    FIX_SUCCESS=true
                    break
                    ;;
                PARTIAL)
                    REMAINING=$(grep "^Remaining Issues:" "$TEMP_DIR/verification-report-iter$ITERATION.md" | awk '{print $3}')
                    echo -e "${YELLOW}⚠️  Partial fix: $REMAINING issue(s) remaining${NC}"

                    if [ $ITERATION -lt $MAX_ITERATIONS ]; then
                        echo -e "${YELLOW}🔄 Attempting another fix iteration...${NC}"
                        echo ""
                        # Update report with remaining issues for next iteration
                        cp "$TEMP_DIR/verification-report-iter$ITERATION.md" "$TEMP_DIR/gosec-report.json"
                    fi
                    ;;
                FAIL)
                    echo -e "${RED}❌ Verification failed${NC}"
                    break
                    ;;
            esac
        else
            echo -e "${RED}❌ Verification step failed${NC}"
            break
        fi
    else
        echo -e "${RED}❌ Fix attempt failed${NC}"
        break
    fi

    ITERATION=$((ITERATION + 1))
done

# Step 4: Generate final report
echo ""
echo -e "${BLUE}[Step 4/4]${NC} Generating final report..."
echo ""

FINAL_REPORT="$TEMP_DIR/security-fix-final-report.md"

cat > "$FINAL_REPORT" << EOF
# Security Fix Report

**Generated:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Project:** $(basename "$(pwd)")
**Total Iterations:** $((ITERATION - 1))

## Summary

EOF

if [ "$FIX_SUCCESS" = true ]; then
    cat >> "$FINAL_REPORT" << EOF
✅ **Status:** SUCCESS

All security issues have been automatically fixed and verified.

### Actions Taken

EOF
    for i in $(seq 1 $((ITERATION - 1))); do
        if [ -f "$TEMP_DIR/security-fixes-iter$i.md" ]; then
            echo "#### Iteration $i" >> "$FINAL_REPORT"
            cat "$TEMP_DIR/security-fixes-iter$i.md" >> "$FINAL_REPORT"
            echo "" >> "$FINAL_REPORT"
        fi
    done

    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✅ All security issues fixed successfully!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "📄 Final report: ${CYAN}$FINAL_REPORT${NC}"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo -e "  1. Review the changes: git diff"
    echo -e "  2. Run tests: go test ./..."
    echo -e "  3. Commit changes: git add -A && git commit -m 'fix: address security issues'"
    echo ""

    exit 0
else
    # Determine remaining issues
    LAST_VERIFICATION="$TEMP_DIR/verification-report-iter$((ITERATION - 1)).md"
    if [ -f "$LAST_VERIFICATION" ]; then
        REMAINING=$(grep "^Remaining Issues:" "$LAST_VERIFICATION" | awk '{print $3}' || echo "unknown")
    else
        REMAINING="unknown"
    fi

    cat >> "$FINAL_REPORT" << EOF
⚠️ **Status:** PARTIAL / FAILED

Could not automatically fix all security issues after $((ITERATION - 1)) iteration(s).
Remaining issues: $REMAINING

### Attempted Fixes

EOF
    for i in $(seq 1 $((ITERATION - 1))); do
        if [ -f "$TEMP_DIR/security-fixes-iter$i.md" ]; then
            echo "#### Iteration $i" >> "$FINAL_REPORT"
            cat "$TEMP_DIR/security-fixes-iter$i.md" >> "$FINAL_REPORT"
            echo "" >> "$FINAL_REPORT"
        fi
    done

    cat >> "$FINAL_REPORT" << EOF

### Manual Intervention Required

Please review the security scan report and fix remaining issues manually:
- Security scan: $TEMP_DIR/security-scan-summary.md
- Original report: $TEMP_DIR/gosec-report.json

Refer to: .claude/skills/local-ci-go/references/security-best-practices.md
EOF

    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}⚠️  Could not fix all issues automatically${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "📄 Final report: ${CYAN}$FINAL_REPORT${NC}"
    echo -e "📄 Remaining issues: ${CYAN}$TEMP_DIR/security-scan-summary.md${NC}"
    echo ""
    echo -e "${YELLOW}Manual fixes required. See report for details.${NC}"
    echo ""

    exit 1
fi
