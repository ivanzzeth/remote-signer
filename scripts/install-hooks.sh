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
    if ! command -v gitleaks &> /dev/null; then
        missing+=("gitleaks (install: go install github.com/zricethezav/gitleaks/v8@latest)")
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
# Pre-commit hook: Unit tests + security checks + rule validation (no e2e)
set -e

export PATH="$HOME/.goenv/shims:$HOME/.goenv/bin:$(go env GOPATH 2>/dev/null)/bin:$PATH"
export GOTOOLCHAIN=local

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

FAILED=0

echo "=== Running pre-commit checks ==="

# 1. Unit tests
echo -n "Running unit tests... "
if go test ./... 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"
    FAILED=1
fi

# 2. Static security analysis with gosec
if command -v gosec &> /dev/null; then
    echo -n "Running gosec... "
    if gosec -quiet -exclude-dir=vendor -exclude-dir=app/metamask-snap -exclude-dir=pkg/js-client -exclude=G104,G301,G304,G306,G402,G703,G705 ./... 2>/dev/null; then
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
        NON_STDLIB=$(echo "$GOVULN_OUTPUT" | python3 -c "
import sys, json
has_non_stdlib = False
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try: obj = json.loads(line)
    except json.JSONDecodeError: continue
    finding = obj.get('finding')
    if finding:
        traces = finding.get('trace', [])
        if traces and traces[0].get('module', '') != 'stdlib':
            has_non_stdlib = True; break
print('yes' if has_non_stdlib else 'no')
" 2>/dev/null)
        if [ "$NON_STDLIB" = "no" ]; then
            echo -e "${YELLOW}WARN${NC}"
            echo "govulncheck: stdlib-only vulnerabilities (no fix available yet)."
        else
            echo -e "${RED}FAIL${NC}"
            echo "govulncheck found vulnerable dependencies."
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

# 5. Gitleaks
if command -v gitleaks &> /dev/null; then
    echo -n "Running gitleaks... "
    if gitleaks protect --staged --no-banner --exit-code 1 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        echo "gitleaks found secrets."
        FAILED=1
    fi
else
    echo -e "${YELLOW}SKIP (gitleaks not installed)${NC}"
fi

# 6. Rule validation
STAGED_RULES=$(git diff --cached --name-only --diff-filter=ACM | grep '^rules/.*\.yaml$' || true)
if [ -n "$STAGED_RULES" ]; then
    echo -n "Validating rule files... "
    if go run ./cmd/remote-signer validate $STAGED_RULES 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        echo "Rule validation failed."
        FAILED=1
    fi
else
    echo -e "Validating rule files... ${GREEN}OK (no staged rule files)${NC}"
fi

echo "=== Pre-commit checks complete ==="

if [ $FAILED -ne 0 ]; then
    echo -e "${RED}Some checks failed. Commit blocked.${NC}"
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
# Pre-push hook: Full test suite + security checks + rule validation + e2e before pushing
set -e

export PATH="$HOME/.goenv/shims:$HOME/.goenv/bin:$(go env GOPATH 2>/dev/null)/bin:$PATH"
export GOTOOLCHAIN=local

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

FAILED=0

echo "=== Running pre-push checks ==="

# 1. Unit tests
echo -n "Running unit tests... "
if go test ./... 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"
    FAILED=1
fi

# 2. Static security analysis with gosec
if command -v gosec &> /dev/null; then
    echo -n "Running gosec... "
    if gosec -quiet -exclude-dir=vendor -exclude-dir=app/metamask-snap -exclude-dir=pkg/js-client -exclude=G104,G301,G304,G306,G402,G703,G705 ./... 2>/dev/null; then
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
        NON_STDLIB=$(echo "$GOVULN_OUTPUT" | python3 -c "
import sys, json
has_non_stdlib = False
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try: obj = json.loads(line)
    except json.JSONDecodeError: continue
    finding = obj.get('finding')
    if finding:
        traces = finding.get('trace', [])
        if traces and traces[0].get('module', '') != 'stdlib':
            has_non_stdlib = True; break
print('yes' if has_non_stdlib else 'no')
" 2>/dev/null)
        if [ "$NON_STDLIB" = "no" ]; then
            echo -e "${YELLOW}WARN${NC}"
            echo "govulncheck: stdlib-only vulnerabilities (no fix available yet)."
        else
            echo -e "${RED}FAIL${NC}"
            echo "govulncheck found vulnerable dependencies."
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

# 5. Gitleaks
if command -v gitleaks &> /dev/null; then
    echo -n "Running gitleaks... "
    if gitleaks protect --staged --no-banner --exit-code 1 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        echo "gitleaks found secrets."
        FAILED=1
    fi
else
    echo -e "${YELLOW}SKIP (gitleaks not installed)${NC}"
fi

# 6. Rule validation
STAGED_RULES=$(git diff --cached --name-only --diff-filter=ACM | grep '^rules/.*\.yaml$' | grep -v '^rules/presets/' || true)
if [ -n "$STAGED_RULES" ]; then
    echo -n "Validating rule files... "
    if go run ./cmd/remote-signer validate $STAGED_RULES 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        echo "Rule validation failed."
        FAILED=1
    fi
else
    echo -e "Validating rule files... ${GREEN}OK (no staged rule files)${NC}"
fi

# 7. E2E tests
STAGED_FOR_E2E=$(git diff --cached --name-only --diff-filter=ACM)
SHOULD_RUN_E2E=0
for f in $STAGED_FOR_E2E; do
    case "$f" in
        *.md|*.rst|docs/*|.github/*|LICENSE*|COPYING*|NOTICE*|SECURITY.md) ;;
        *.png|*.jpg|*.jpeg|*.gif|*.svg|*.webp|*.ico|.gitignore|.gitattributes|.editorconfig|.secrets.baseline) ;;
        *)
            SHOULD_RUN_E2E=1
            break
            ;;
    esac
done
if [ "$SHOULD_RUN_E2E" -eq 1 ]; then
    echo -n "Running e2e tests... "
    if GOMAXPROCS=1 E2E_API_PORT=18548 go test -p 1 -tags e2e ./e2e/... -count=1 -timeout 10m -skip 'TestSimulate_' 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        echo "E2E tests failed."
        FAILED=1
    fi
else
    echo -e "Running e2e tests... ${YELLOW}SKIP${NC} (doc-only changes)"
fi

echo "=== Pre-push checks complete ==="

if [ $FAILED -ne 0 ]; then
    echo -e "${RED}Some checks failed. Push blocked.${NC}"
    exit 1
fi
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
echo "  pre-commit : unit tests, gosec, govulncheck, go vet, gitleaks, rule validation"
echo "  pre-push   : all pre-commit checks + e2e tests"
echo ""
echo "To skip hooks (NOT recommended): git commit --no-verify"
