#!/bin/bash
# =============================================================================
# Install Git Hooks for Security Checks
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
# Resolve the actual git dir (handles submodules where .git is a file)
GIT_DIR="$(cd "$PROJECT_DIR" && git rev-parse --git-dir)"
if [[ "$GIT_DIR" != /* ]]; then
    GIT_DIR="$PROJECT_DIR/$GIT_DIR"
fi
HOOKS_DIR="$GIT_DIR/hooks"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# =============================================================================
# Check prerequisites
# =============================================================================
check_tools() {
    local missing=()

    if ! command -v go &> /dev/null; then
        missing+=("go")
    fi
    if ! command -v gosec &> /dev/null; then
        missing+=("gosec (install: go install github.com/securego/gosec/v2/cmd/gosec@latest)")
    fi
    if ! command -v govulncheck &> /dev/null; then
        missing+=("govulncheck (install: go install golang.org/x/vuln/cmd/govulncheck@latest)")
    fi
    if ! command -v forge &> /dev/null; then
        missing+=("forge (install: curl -L https://foundry.paradigm.xyz | bash && foundryup)")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        log_warn "Missing tools (hooks will skip unavailable checks):"
        for tool in "${missing[@]}"; do
            echo "  - $tool"
        done
    fi
}

# =============================================================================
# Install pre-commit hook
# =============================================================================
install_pre_commit() {
    local hook_path="$HOOKS_DIR/pre-commit"

    cat > "$hook_path" << 'HOOK_EOF'
#!/bin/bash
# =============================================================================
# Pre-commit hook: Security checks before every commit
# Installed by: scripts/install-hooks.sh
# =============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

FAILED=0

echo "=== Running pre-commit security checks ==="

# 1. Check for error suppression (project rule: _ = xxx is forbidden)
echo -n "Checking for suppressed errors... "
# Only check staged Go files (excluding vendor and test files)
STAGED_GO_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.go$' | grep -v '_test\.go$' | grep -v 'vendor/' || true)
if [ -n "$STAGED_GO_FILES" ]; then
    SUPPRESSED=$(echo "$STAGED_GO_FILES" | xargs grep -n '_ =' 2>/dev/null | grep -v '_ = .*(/\*\|//\|range\|,)' || true)
    if [ -n "$SUPPRESSED" ]; then
        echo -e "${RED}FAIL${NC}"
        echo "Found suppressed errors (forbidden by project rules):"
        echo "$SUPPRESSED"
        FAILED=1
    else
        echo -e "${GREEN}OK${NC}"
    fi
else
    echo -e "${GREEN}OK (no staged Go files)${NC}"
fi

# 2. Static security analysis with gosec
if command -v gosec &> /dev/null; then
    echo -n "Running gosec... "
    if gosec -quiet -exclude-dir=vendor -exclude-dir=app/metamask-snap -exclude-dir=pkg/js-client ./... 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        echo "gosec found security issues. Run 'gosec ./...' for details."
        FAILED=1
    fi
else
    echo -e "${YELLOW}SKIP (gosec not installed)${NC}"
fi

# 3. Dependency vulnerability check with govulncheck
if command -v govulncheck &> /dev/null; then
    echo -n "Running govulncheck... "
    if govulncheck ./... 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        echo "govulncheck found vulnerable dependencies. Run 'govulncheck ./...' for details."
        FAILED=1
    fi
else
    echo -e "${YELLOW}SKIP (govulncheck not installed)${NC}"
fi

# 4. Go vet
echo -n "Running go vet... "
if go vet ./... 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"
    FAILED=1
fi

# 5. Check for plaintext secrets in staged files
echo -n "Checking for plaintext secrets... "
SECRETS_FOUND=$(git diff --cached --diff-filter=ACM -U0 -- ':!*_test.go' | grep -v '^@@' | grep -iE '(private_key|password|secret|token)\s*[:=]\s*"[^$\{]' | grep -v '_env' | grep -v 'example' | grep -v '#' | grep -viE '(gasToken|paymentToken|refundReceiver|collateralToken|quoteToken)\s*:' || true)
if [ -n "$SECRETS_FOUND" ]; then
    echo -e "${RED}FAIL${NC}"
    echo "Possible plaintext secrets detected in staged changes:"
    echo "$SECRETS_FOUND"
    FAILED=1
else
    echo -e "${GREEN}OK${NC}"
fi

# 6. Validate rule YAML files (only when rules are staged)
STAGED_RULES=$(git diff --cached --name-only --diff-filter=ACM | grep '^rules/.*\.yaml$' || true)
if [ -n "$STAGED_RULES" ]; then
    if command -v forge &> /dev/null; then
        echo -n "Validating rule files... "
        # shellcheck disable=SC2086
        if go run ./cmd/validate-rules/ $STAGED_RULES 2>/dev/null; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${RED}FAIL${NC}"
            echo "Rule validation failed. Run 'go run ./cmd/validate-rules/ -v rules/*.yaml' for details."
            FAILED=1
        fi
    else
        echo -e "${YELLOW}SKIP rule validation (forge not installed)${NC}"
    fi
else
    echo -e "Validating rule files... ${GREEN}OK (no staged rule files)${NC}"
fi

# 7. Run e2e tests (using port 18548 to avoid conflict with production on 8548)
echo -n "Running e2e tests... "
if E2E_API_PORT=18548 go test -tags e2e ./e2e/... -count=1 -timeout 120s 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"
    echo "E2E tests failed. Run 'E2E_API_PORT=18548 go test -tags e2e -v ./e2e/...' for details."
    FAILED=1
fi

echo "=== Pre-commit checks complete ==="

if [ $FAILED -ne 0 ]; then
    echo -e "${RED}Some checks failed. Commit blocked.${NC}"
    echo "Fix the issues above or use 'git commit --no-verify' to skip (NOT recommended)."
    exit 1
fi
HOOK_EOF

    chmod +x "$hook_path"
    log_info "Installed pre-commit hook"
}

# =============================================================================
# Install pre-push hook
# =============================================================================
install_pre_push() {
    local hook_path="$HOOKS_DIR/pre-push"

    cat > "$hook_path" << 'HOOK_EOF'
#!/bin/bash
# =============================================================================
# Pre-push hook: Full test suite before pushing
# Installed by: scripts/install-hooks.sh
# =============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo "=== Running pre-push checks ==="

# 1. Run unit tests
echo "Running unit tests..."
if ! go test ./... 2>&1; then
    echo -e "${RED}Unit tests failed. Push blocked.${NC}"
    exit 1
fi
echo -e "${GREEN}Unit tests passed${NC}"

echo "=== Pre-push checks complete ==="
HOOK_EOF

    chmod +x "$hook_path"
    log_info "Installed pre-push hook"
}

# =============================================================================
# Main
# =============================================================================
log_info "Installing git hooks for remote-signer..."

# Ensure hooks directory exists
mkdir -p "$HOOKS_DIR"

check_tools
install_pre_commit
install_pre_push

log_info "Git hooks installed successfully!"
log_info "Hooks location: $HOOKS_DIR"
echo ""
echo "Installed hooks:"
echo "  pre-commit : gosec, govulncheck, go vet, error suppression check, secret detection, rule validation, e2e tests"
echo "  pre-push   : full unit test suite (includes rule validation via TestRulesDirectoryValidation)"
echo ""
echo "To skip hooks (NOT recommended): git commit --no-verify"
