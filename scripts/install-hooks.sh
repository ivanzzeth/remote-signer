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
    if ! command -v gitleaks &> /dev/null; then
        missing+=("gitleaks (install: go install github.com/zricethezav/gitleaks/v8@latest)")
    fi
    if ! command -v detect-secrets &> /dev/null; then
        missing+=("detect-secrets (install: pip install detect-secrets)")
    fi
    if ! command -v semgrep &> /dev/null; then
        missing+=("semgrep (install: pip install semgrep)")
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

# Ensure goenv and GOPATH/bin are on PATH (hooks run in minimal shell)
export PATH="$HOME/.goenv/shims:$HOME/.goenv/bin:$(go env GOPATH 2>/dev/null)/bin:$PATH"
export GOTOOLCHAIN=local

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
    GOVULN_OUTPUT=$(govulncheck -format json ./... 2>/dev/null)
    GOVULN_EXIT=$?
    if [ $GOVULN_EXIT -eq 0 ]; then
        echo -e "${GREEN}OK${NC}"
    else
        # Check if all findings are stdlib-only (no available fix via go get)
        NON_STDLIB=$(echo "$GOVULN_OUTPUT" | python3 -c "
import sys, json
has_non_stdlib = False
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        continue
    finding = obj.get('finding')
    if finding:
        traces = finding.get('trace', [])
        if traces and traces[0].get('module', '') != 'stdlib':
            has_non_stdlib = True
            break
print('yes' if has_non_stdlib else 'no')
" 2>/dev/null)
        if [ "$NON_STDLIB" = "no" ]; then
            echo -e "${YELLOW}WARN${NC}"
            echo "govulncheck: stdlib-only vulnerabilities (no fix available yet). Run 'govulncheck ./...' for details."
        else
            echo -e "${RED}FAIL${NC}"
            echo "govulncheck found vulnerable dependencies. Run 'govulncheck ./...' for details."
            FAILED=1
        fi
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
SECRETS_FOUND=$(git diff --cached --diff-filter=ACM -U0 -- ':!*_test.go' | grep -v '^@@' | grep -iE '(private_key|password|secret|token)\s*[:=]\s*"[^$\{]' | grep -v '_env' | grep -v 'example' | grep -v '#' | grep -v 'Render(' | grep -v 'fmt\.' | grep -viE '(gasToken|paymentToken|refundReceiver|collateralToken|quoteToken)\s*:' || true)
if [ -n "$SECRETS_FOUND" ]; then
    echo -e "${RED}FAIL${NC}"
    echo "Possible plaintext secrets detected in staged changes:"
    echo "$SECRETS_FOUND"
    FAILED=1
else
    echo -e "${GREEN}OK${NC}"
fi

# 5a. Gitleaks: scan staged changes for secrets
if command -v gitleaks &> /dev/null; then
    echo -n "Running gitleaks... "
    if gitleaks protect --staged --no-banner --exit-code 1 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        echo "gitleaks found secrets in staged changes. Run 'gitleaks protect --staged -v' for details."
        FAILED=1
    fi
else
    echo -e "${YELLOW}SKIP (gitleaks not installed)${NC}"
fi

# 5b. detect-secrets: complement gitleaks with additional detectors
if command -v detect-secrets &> /dev/null; then
    echo -n "Running detect-secrets... "
    STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -v 'vendor/' | grep -v 'node_modules/' | grep -v 'go\.sum' | grep -v '\.secrets\.baseline' || true)
    if [ -n "$STAGED_FILES" ]; then
        if [ -f .secrets.baseline ]; then
            # Scan staged files, update baseline in-place, then audit for unaudited secrets
            # shellcheck disable=SC2086
            detect-secrets scan --baseline .secrets.baseline $STAGED_FILES 2>/dev/null || true
            # Re-stage the baseline so the updated scan results are included in this commit
            git add .secrets.baseline 2>/dev/null || true
            if ! detect-secrets audit --report --baseline .secrets.baseline 2>/dev/null | grep -q '"results":.*\[\]'; then
                # Simpler: just check if scan found new secrets by comparing result counts
                NEW_SECRETS=$(python3 -c "
import json, sys
try:
    b = json.load(open('.secrets.baseline'))
    total = sum(len(v) for v in b.get('results', {}).values())
    unaudited = sum(1 for v in b.get('results', {}).values() for s in v if not s.get('is_verified') and not s.get('is_secret') == False)
    if unaudited > 0:
        print(f'{unaudited} unaudited potential secrets')
        sys.exit(1)
except Exception:
    pass
" 2>/dev/null) || true
                if [ -n "$NEW_SECRETS" ]; then
                    echo -e "${YELLOW}WARN${NC}"
                    echo "detect-secrets: $NEW_SECRETS (run 'detect-secrets audit .secrets.baseline' to review)"
                else
                    echo -e "${GREEN}OK${NC}"
                fi
            else
                echo -e "${GREEN}OK${NC}"
            fi
        else
            # No baseline; scan staged files for any secrets
            # shellcheck disable=SC2086
            DS_OUTPUT=$(detect-secrets scan $STAGED_FILES 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
findings = [(f, s) for f, secrets in data.get('results', {}).items() for s in secrets]
for f, s in findings:
    print(f\"  {f}:{s['line_number']} ({s['type']})\")
" 2>/dev/null || true)
            if [ -n "$DS_OUTPUT" ]; then
                echo -e "${RED}FAIL${NC}"
                echo "detect-secrets found potential secrets:"
                echo "$DS_OUTPUT"
                FAILED=1
            else
                echo -e "${GREEN}OK${NC}"
            fi
        fi
    else
        echo -e "${GREEN}OK (no staged files to scan)${NC}"
    fi
else
    echo -e "${YELLOW}SKIP (detect-secrets not installed)${NC}"
fi

# 5c. Semgrep: SAST for JS/TS security issues (only when JS/TS files are staged)
STAGED_JS_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(js|ts|jsx|tsx)$' | grep -v 'node_modules/' | grep -v 'dist/' || true)
if [ -n "$STAGED_JS_FILES" ]; then
    if command -v semgrep &> /dev/null; then
        echo -n "Running semgrep (JS/TS)... "
        # shellcheck disable=SC2086
        if semgrep scan --config=auto --quiet --error $STAGED_JS_FILES 2>/dev/null; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${RED}FAIL${NC}"
            echo "semgrep found security issues. Run 'semgrep scan --config=auto <files>' for details."
            FAILED=1
        fi
    else
        echo -e "${YELLOW}SKIP semgrep (not installed)${NC}"
    fi
fi

# 5d. ESLint security plugin (only when JS/TS files in pkg/js-client are staged)
STAGED_JSCLIENT_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '^pkg/js-client/src/.*\.\(ts\|js\)$' || true)
if [ -n "$STAGED_JSCLIENT_FILES" ]; then
    if [ -f pkg/js-client/node_modules/.bin/eslint ]; then
        echo -n "Running eslint-plugin-security... "
        # shellcheck disable=SC2086
        if (cd pkg/js-client && npx eslint --no-error-on-unmatched-pattern $STAGED_JSCLIENT_FILES 2>/dev/null); then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${RED}FAIL${NC}"
            echo "ESLint security checks failed. Run 'cd pkg/js-client && npx eslint src' for details."
            FAILED=1
        fi
    else
        echo -e "${YELLOW}SKIP eslint (run 'cd pkg/js-client && npm install' first)${NC}"
    fi
fi

# 5e. npm audit: check JS dependency vulnerabilities (only when package files change)
STAGED_PKG_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '(package\.json|package-lock\.json)$' | grep -v 'node_modules/' || true)
if [ -n "$STAGED_PKG_FILES" ]; then
    if command -v npm &> /dev/null; then
        echo -n "Running npm audit... "
        if (cd pkg/js-client && npm audit --audit-level=high 2>/dev/null); then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${RED}FAIL${NC}"
            echo "npm audit found high/critical vulnerabilities. Run 'cd pkg/js-client && npm audit' for details."
            FAILED=1
        fi
    fi
fi

# 6. Validate rule YAML files (only when rules are staged)
STAGED_RULES=$(git diff --cached --name-only --diff-filter=ACM | grep '^rules/.*\.yaml$' | grep -v '^rules/presets/' || true)
if [ -n "$STAGED_RULES" ]; then
    if command -v forge &> /dev/null; then
        echo -n "Validating rule files... "
        # shellcheck disable=SC2086
        if go run ./cmd/remote-signer-validate-rules/ $STAGED_RULES 2>/dev/null; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${RED}FAIL${NC}"
            echo "Rule validation failed. Run 'go run ./cmd/remote-signer-validate-rules/ -v rules/*.yaml' or 'remote-signer-validate-rules -v rules/*.yaml' for details."
            FAILED=1
        fi
    else
        echo -e "${YELLOW}SKIP rule validation (forge not installed)${NC}"
    fi
else
    echo -e "Validating rule files... ${GREEN}OK (no staged rule files)${NC}"
fi

# 6a. TUI changed => version must change (single source: cmd/remote-signer/main.go or internal/buildinfo)
STAGED_TUI=$(git diff --cached --name-only --diff-filter=ACM | grep '^tui/' || true)
if [ -n "$STAGED_TUI" ]; then
    echo -n "TUI changed; checking version bump... "
    VERSION_FILES="cmd/remote-signer/main.go internal/buildinfo/buildinfo.go"
    VERSION_CHANGED=""
    for f in $VERSION_FILES; do
        if [ -f "$f" ]; then
            if git diff --cached -- "$f" | grep -qE '^[+-].*[Vv]ersion\s*=\s*"[^"]*"'; then
                VERSION_CHANGED=1
                break
            fi
        fi
    done
    if [ -z "$VERSION_CHANGED" ]; then
        echo -e "${RED}FAIL${NC}"
        echo "You changed files under tui/ but did not update the version."
        echo "Update the version in cmd/remote-signer/main.go (const version = \"x.y.z\") or internal/buildinfo/buildinfo.go (Version = \"x.y.z\") and stage it."
        FAILED=1
    else
        echo -e "${GREEN}OK${NC}"
    fi
else
    echo -e "TUI version check... ${GREEN}OK (no staged tui/ changes)${NC}"
fi

# 6b. Any cmd/<name> with staged changes: if that command's main.go defines version, it must be bumped in this commit
STAGED_CMD_DIRS=$(git diff --cached --name-only --diff-filter=ACM | grep '^cmd/' | cut -d'/' -f2 | sort -u)
CMD_VERSION_FAILED=""
for dir in $STAGED_CMD_DIRS; do
    main_go="cmd/$dir/main.go"
    if [ -f "$main_go" ] && grep -qE 'const version\s*=' "$main_go" 2>/dev/null; then
        if ! git diff --cached -- "$main_go" | grep -qE '^[+-].*version\s*=\s*"[^"]*"'; then
            CMD_VERSION_FAILED="${CMD_VERSION_FAILED}  - cmd/$dir: update const version in $main_go and stage it\n"
        fi
    fi
done
if [ -n "$CMD_VERSION_FAILED" ]; then
    echo -e "Cmd version bump... ${RED}FAIL${NC}"
    echo "You changed files under cmd/<name>/ but did not bump the version in that command's main.go:"
    echo -e "$CMD_VERSION_FAILED"
    FAILED=1
elif [ -n "$STAGED_CMD_DIRS" ]; then
    echo -e "Cmd version check... ${GREEN}OK${NC}"
fi

# 7. Run e2e tests (using port 18548 to avoid conflict with production on 8548). No skip; long timeout for budget/schedule e2e.
echo -n "Running e2e tests... "
# Exclude TestSimulate_* (requires external RPC gateway, too slow for pre-commit)
if E2E_API_PORT=18548 go test -tags e2e ./e2e/... -count=1 -timeout 10m -skip 'TestSimulate_' 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"
    echo "E2E tests failed. Run 'E2E_API_PORT=18548 go test -tags e2e -v -timeout 10m ./e2e/...' for details."
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

# Ensure goenv and GOPATH/bin are on PATH (hooks run in minimal shell)
export PATH="$HOME/.goenv/shims:$HOME/.goenv/bin:$(go env GOPATH 2>/dev/null)/bin:$PATH"
export GOTOOLCHAIN=local

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
echo "  pre-commit : gosec, govulncheck, go vet, error suppression, gitleaks, detect-secrets, semgrep, eslint-security, npm audit, rule validation, tui-version-bump (if tui/ changed), cmd-version-bump (if cmd/<name>/ changed and main.go has version), e2e tests"
echo "  pre-push   : full unit test suite (includes rule validation via TestRulesDirectoryValidation)"
echo ""
echo "To skip hooks (NOT recommended): git commit --no-verify"
