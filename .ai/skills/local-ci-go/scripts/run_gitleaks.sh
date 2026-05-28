#!/bin/bash
# Run gitleaks to detect secrets and sensitive information

set -e

echo "🔐 Scanning for secrets and sensitive information..."
echo ""

# Check if gitleaks is installed
if ! command -v gitleaks &> /dev/null; then
    echo "❌ gitleaks is not installed"
    echo ""
    echo "Install from: https://github.com/gitleaks/gitleaks#installing"
    echo ""
    echo "Or run:"
    echo "  bash .claude/skills/local-ci-go/scripts/install_tools.sh"
    exit 1
fi

# Check if this is a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "⚠️  Not a git repository"
    echo "Gitleaks works best with git repositories"
    echo ""
    echo "Scanning current directory without git history..."
    if gitleaks detect --no-git --verbose 2>&1 | tee gitleaks_output.txt; then
        echo ""
        echo "✅ No secrets detected!"
        rm -f gitleaks_output.txt
        exit 0
    else
        EXIT_CODE=$?
        echo ""
        echo "❌ Secrets detected!"
        echo ""
        echo "See gitleaks_output.txt for details"
        exit $EXIT_CODE
    fi
fi

# Check for custom gitleaks configuration
if [ -f .gitleaks.toml ]; then
    echo "Using custom configuration: .gitleaks.toml"
    CONFIG_ARG="--config .gitleaks.toml"
else
    echo "Using default gitleaks configuration"
    CONFIG_ARG=""
fi

echo ""

# Determine scan mode
SCAN_MODE="${1:-staged}"

case "$SCAN_MODE" in
    staged)
        echo "Scanning staged changes (git diff --cached)..."
        echo "This checks files you're about to commit"
        echo ""
        if gitleaks protect $CONFIG_ARG --staged --verbose 2>&1 | tee gitleaks_output.txt; then
            echo ""
            echo "✅ No secrets detected in staged changes!"
            rm -f gitleaks_output.txt
            exit 0
        else
            EXIT_CODE=$?
        fi
        ;;

    uncommitted)
        echo "Scanning uncommitted changes (working directory)..."
        echo "This checks all modified files, staged or not"
        echo ""
        if gitleaks detect $CONFIG_ARG --no-git --verbose 2>&1 | tee gitleaks_output.txt; then
            echo ""
            echo "✅ No secrets detected in uncommitted changes!"
            rm -f gitleaks_output.txt
            exit 0
        else
            EXIT_CODE=$?
        fi
        ;;

    history)
        echo "Scanning entire git history..."
        echo "⚠️  This may take a while for large repositories"
        echo ""
        if gitleaks detect $CONFIG_ARG --verbose 2>&1 | tee gitleaks_output.txt; then
            echo ""
            echo "✅ No secrets detected in git history!"
            rm -f gitleaks_output.txt
            exit 0
        else
            EXIT_CODE=$?
        fi
        ;;

    *)
        echo "❌ Invalid scan mode: $SCAN_MODE"
        echo ""
        echo "Usage: $0 [staged|uncommitted|history]"
        echo "  staged      - Scan staged changes (default)"
        echo "  uncommitted - Scan all uncommitted changes"
        echo "  history     - Scan entire git history"
        exit 1
        ;;
esac

# If we get here, secrets were detected
echo ""
echo "❌ Secrets detected!"
echo ""
echo "⚠️  CRITICAL: If these secrets are real, you must:"
echo "  1. Rotate/revoke the compromised credentials IMMEDIATELY"
echo "  2. Remove secrets from code"
echo "  3. If already committed, remove from git history"
echo ""
echo "Common fixes:"
echo ""
echo "1. Use environment variables:"
echo "   // Bad"
echo "   apiKey := \"sk-1234567890abcdef\""
echo ""
echo "   // Good"
echo "   apiKey := os.Getenv(\"API_KEY\")"
echo ""
echo "2. Use configuration files (add to .gitignore):"
echo "   // config.yaml (in .gitignore)"
echo "   api_key: sk-1234567890abcdef"
echo ""
echo "3. Use secret management services:"
echo "   - AWS Secrets Manager"
echo "   - HashiCorp Vault"
echo "   - Azure Key Vault"
echo ""
echo "4. If false positive, add to .gitleaksignore:"
echo "   path/to/file.go:line_number"
echo ""
echo "5. If already committed, remove from history:"
echo "   git filter-branch --force --index-filter \\"
echo "     'git rm --cached --ignore-unmatch path/to/file' \\"
echo "     --prune-empty --tag-name-filter cat -- --all"
echo ""
echo "   Or use BFG Repo-Cleaner: https://rtyley.github.io/bfg-repo-cleaner/"
echo ""
echo "For detailed information, see:"
echo "  .claude/skills/local-ci-go/references/security-best-practices.md"
echo ""

rm -f gitleaks_output.txt
exit $EXIT_CODE
