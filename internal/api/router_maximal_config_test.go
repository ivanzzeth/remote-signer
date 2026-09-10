package api

import (
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"sort"
	"testing"

	"gorm.io/gorm"

	evmhandler "github.com/ivanzzeth/remote-signer/internal/api/handler/evm"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/auth"
	"github.com/ivanzzeth/remote-signer/internal/core/ports"
	"github.com/ivanzzeth/remote-signer/internal/core/registry"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/settings"
	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------- The maximal-configuration route registration gate ----------
//
// # What breaks without it
//
// Go 1.22's ServeMux panics *at registration time* when two patterns overlap
// without either being a strict subset of the other — `POST /a/{x}/c` against
// `POST /a/b/{y}`, which both match `/a/b/c` and neither contains. That panic
// happens inside NewRouter, before any listener exists: the daemon does not
// start. It is not a request-time 500 somebody can retry around.
//
// setupRoutes registers behind ~13 conditional `if r.config.X != nil` branches,
// so a conflicting pair can sit latent in a branch nobody's configuration
// happens to enable, and surface as "the daemon won't boot" on the one
// installation that enables it. Nothing else covers it: e2e/test_server.go:639-656
// populates 15 of RouterConfig's 29 fields and leaves 14 zero (among them
// RPCProvider, RuleEngine, IPWhitelistConfigForRead, TemplateRegistry,
// PresetRegistry, RequestRepo and Modules), so those branches never fire in e2e
// either — and e2e is in any case the wrong place to find out, being minutes
// away from the edit that caused it rather than the 2.5s `http` layer.
//
// This test enables all of them at once — the configuration no real deployment
// might have, which is exactly why nothing else covers it — and asserts the
// registration completes.
//
// # ⛔ Why a hand-written RouterConfig literal is not enough
//
// The value of this test is entirely in the word *maximal*. A literal listing
// today's fields is maximal for exactly as long as nobody adds a field: the
// next field lands with its `if` branch, the branch registers patterns nobody
// checked for conflicts, and this test stays green while covering strictly less
// than it claims. That is the same failure this file exists to prevent, one
// level up — a gate that has quietly stopped watching is worse than no gate.
//
// So the literal is checked against the struct by reflection
// (assertEveryFieldPopulated): every exported field of RouterConfig must be
// non-zero. Add a field and forget it here and this test fails by name, telling
// you where to put the stub. ⚠️ Reflection cannot synthesise a value for an
// interface-typed field, so the stubs below stay hand-written — what is
// automated is the *completeness check*, which is the part that goes stale.

// ---------- stubs ----------
//
// Each stub embeds the interface it satisfies: the method set is promoted from
// a nil interface value, so the type compiles as an implementation and any call
// panics. Deliberate — nothing here is meant to serve a request. Registration
// is the whole subject, and a stub with real behaviour would drag a database
// into the `http` layer (2.5s, no IO) for no gain.

type stubRuleRepo struct{ ports.RuleRepository }
type stubAuditRepo struct{ ports.AuditRepository }
type stubAPIKeyRepo struct{ ports.APIKeyRepository }
type stubSignerOwnershipRepo struct {
	ports.SignerOwnershipRepository
}
type stubSignerAccessRepo struct{ ports.SignerAccessRepository }
type stubSignerRepo struct{ ports.SignerRepository }
type stubBudgetRepo struct{ ports.BudgetRepository }
type stubPresetRepo struct{ ports.PresetRepository }
type stubWalletRepo struct{ ports.WalletRepository }
type stubTemplateRepo struct{ ports.TemplateRepository }
type stubRequestRepo struct{ ports.RequestRepository }
type stubRequestSimulationRepo struct {
	storage.RequestSimulationRepository
}
type stubSignerManager struct{ evm.SignerManager }
type stubRuleEngine struct{ rule.RuleEngine }
type stubSimulator struct{ simulation.Simulator }
type stubTransactionRecorder struct{ evmhandler.TransactionRecorder }

// maximalRouterConfig returns a RouterConfig with every field populated, so
// that every conditional registration branch in setupRoutes fires.
//
// ⚠️ Every value here is a stub or a zero-valued struct: setupRoutes only
// stores these and consults them for nil-ness, and the assertion is about which
// patterns reach the mux, not about what the handlers do with their deps.
func maximalRouterConfig(t *testing.T) RouterConfig {
	t.Helper()

	templateRepo := &stubTemplateRepo{}
	apiKeyRepo := &stubAPIKeyRepo{}

	cfg := RouterConfig{
		Modules: []Module{&stubModule{name: "maximal-config-probe", routes: func(reg RouteRegistrar) {
			reg.Handle("GET /maximal-config-probe", Public("test fixture: proves Modules were mounted"), okHandler("probe"))
		}}},
		Version:                  "maximal-config-test",
		IPWhitelistConfig:        &middleware.IPWhitelist{},
		IPWhitelistConfigForRead: &ports.IPWhitelist{},
		SolidityValidator:        &evm.SolidityRuleValidator{},
		JSEvaluator:              &evm.JSRuleEvaluator{},
		Template: &TemplateConfig{
			TemplateRepo:    templateRepo,
			TemplateService: &service.TemplateService{},
		},
		ApprovalGuard:         &service.ManualApprovalGuard{},
		APIKeyRepo:            apiKeyRepo,
		SignerOwnershipRepo:   &stubSignerOwnershipRepo{},
		SignerAccessRepo:      &stubSignerAccessRepo{},
		SignerRepo:            &stubSignerRepo{},
		AlertService:          &middleware.SecurityAlertService{},
		AuditLogger:           &audit.AuditLogger{},
		AuditRetentionDays:    90,
		BudgetRepo:            &stubBudgetRepo{},
		PresetRepo:            &stubPresetRepo{},
		PresetsDB:             &gorm.DB{},
		TemplateRegistry:      &registry.TemplateRegistry{},
		PresetRegistry:        &registry.PresetRegistry{},
		WalletRepo:            &stubWalletRepo{},
		SettingsManager:       settings.NewManager(nil, testLogger()),
		Simulator:             &stubSimulator{},
		SimulationRule:        &evm.SimulationBudgetRule{},
		RuleEngine:            &stubRuleEngine{},
		RPCProvider:           &evm.RPCProvider{},
		TransactionService:    &stubTransactionRecorder{},
		RequestSimulationRepo: &stubRequestSimulationRepo{},
		RequestRepo:           &stubRequestRepo{},
	}

	assertEveryFieldPopulated(t, cfg)
	return cfg
}

// assertEveryFieldPopulated is the part that cannot go stale. It walks
// RouterConfig by reflection and refuses any exported field left at its zero
// value, so a field added next month fails here by name instead of silently
// carrying an unexercised registration branch.
func assertEveryFieldPopulated(t *testing.T, cfg RouterConfig) {
	t.Helper()

	v := reflect.ValueOf(cfg)
	ty := v.Type()

	var missing []string
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		if !f.IsExported() {
			// RouterConfig has none today. If one appears, it cannot gate a
			// registration branch from outside the package, so it is not this
			// test's business.
			continue
		}
		if v.Field(i).IsZero() {
			missing = append(missing, f.Name+" "+f.Type.String())
		}
	}
	if len(missing) == 0 {
		return
	}
	sort.Strings(missing)
	t.Fatalf("maximalRouterConfig leaves %d RouterConfig field(s) at their zero value:\n  %v\n\n"+
		"⛔ A zero field means setupRoutes' `if r.config.X != nil` branch for it never fires, so whatever "+
		"patterns that branch registers are not checked for ServeMux conflicts by this test — and a conflict "+
		"there panics inside NewRouter, i.e. the daemon does not start, on whichever deployment enables the "+
		"field. Populate it in maximalRouterConfig (a stub embedding the interface is enough; nothing is "+
		"called) rather than skipping it here.",
		len(missing), missing)
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newMaximalRouter builds the router under the maximal configuration, turning
// the registration panic into a readable failure.
func newMaximalRouter(t *testing.T) *Router {
	t.Helper()

	var (
		r   *Router
		err error
	)
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("NewRouter panicked while registering routes: %v\n\n"+
					"⛔ This is a startup failure, not a request failure: the panic happens inside NewRouter, "+
					"before the listener exists, so the daemon does not boot at all. The usual cause is two "+
					"http.ServeMux patterns that overlap without one being a strict subset of the other "+
					"(`POST /a/{x}/c` vs `POST /a/b/{y}`, both matching /a/b/c) — Go 1.22's mux rejects that "+
					"pair at registration. The other cause is route_auth.go's own guards: a duplicate pattern, "+
					"or a RouteAuth with no decision/reason.", rec)
			}
		}()
		r, err = NewRouter(
			&auth.Verifier{},
			&service.SignService{},
			&stubSignerManager{},
			&stubRuleRepo{},
			&stubAuditRepo{},
			testLogger(),
			maximalRouterConfig(t),
		)
	}()
	if err != nil {
		t.Fatalf("NewRouter returned an error under the maximal config: %v\n\n"+
			"⚠️ An error here also defeats the test: setupRoutes returns early, so every registration after "+
			"the failing constructor never runs and no conflict among those patterns can be detected.", err)
	}
	return r
}

// TestNewRouter_MaximalConfigDoesNotPanic is the gate itself: with every
// conditional branch enabled, registration must complete.
func TestNewRouter_MaximalConfigDoesNotPanic(t *testing.T) {
	r := newMaximalRouter(t)

	// ⭐ "It did not panic" is satisfied just as well by a config that registers
	// nothing at all, so the count is part of the assertion. The floor is
	// deliberately well below today's number: this is a smoke floor against a
	// silently empty router, not a ratchet on the route count — routes come and
	// go, and a second gate on the same number would only produce false reds.
	const minRoutes = 40
	got := len(r.RouteAuthorizations())
	if got < minRoutes {
		t.Fatalf("maximal config registered only %d patterns, want at least %d — "+
			"a router that registers (almost) nothing cannot conflict with itself, so it would pass the "+
			"no-panic assertion while proving nothing", got, minRoutes)
	}
}

// TestNewRouter_MaximalConfigFiresEveryConditionalBranch checks the other half:
// that the stubs are actually sufficient to switch each branch on. A stub that
// is non-nil but makes its branch bail out (an `accessService` that failed to
// build, say) leaves the branch's patterns unregistered — and the no-panic
// assertion above would still be green, because the patterns that could
// conflict were never handed to the mux.
//
// Each entry names one conditional branch in setupRoutes by a pattern only that
// branch registers.
func TestNewRouter_MaximalConfigFiresEveryConditionalBranch(t *testing.T) {
	r := newMaximalRouter(t)
	registered := r.RouteAuthorizations()

	for _, tc := range []struct{ gatedBy, pattern string }{
		{"Modules", "GET /maximal-config-probe"},
		{"BudgetRepo", "GET /api/v1/evm/budgets"},
		{"Simulator", "POST /api/v1/evm/simulate"},
		{"RequestSimulationRepo", "/api/v1/evm/simulations"},
		{"RPCProvider", "POST /api/v1/evm/broadcast"},
		{"RPCProvider (rpc proxy)", "POST /api/v1/evm/rpc/"},
		{"RuleEngine + signer access service", "POST /api/v1/evm/sign/batch"},
		{"APIKeyRepo", "/api/v1/api-keys"},
		{"IPWhitelistConfigForRead", "GET /api/v1/acls/ip-whitelist"},
		{"SettingsManager", "/api/v1/admin/settings/"},
		{"SettingsManager (SPA catch-all)", "/"},
		{"Template", "/api/v1/templates"},
		{"PresetRepo + Template", "/api/v1/presets"},
		{"TemplateRegistry + PresetRegistry", "POST /api/v1/registry/refresh"},
	} {
		if _, ok := registered[tc.pattern]; !ok {
			t.Errorf("pattern %q is absent, so the branch gated by %s did not register — "+
				"its patterns were never handed to the mux and a conflict among them would go unseen here",
				tc.pattern, tc.gatedBy)
		}
	}

	// ⛔ The WalletRepo branch used to be one row above, named by the literal
	// "/api/v1/wallets". S3 turned that branch into eight patterns, and writing
	// eight literals here would make this file a second copy of the wallet route
	// table — the drift wallet_routes_test.go exists to prevent. So the patterns
	// come from the module, and what is asserted is stronger than the row it
	// replaces: *every* wallet pattern reached the real router's mux, not just
	// one of them. A route added to walletsModule and lost to a conditional will
	// fail here by name.
	walletsMod, err := NewWalletsModule(&stubWalletRepo{}, &stubSignerOwnershipRepo{}, &stubSignerAccessRepo{}, testLogger())
	if err != nil {
		t.Fatalf("building the wallets module: %v", err)
	}
	if walletsMod == nil {
		t.Fatal("NewWalletsModule returned no module for a non-nil repo, so this check would assert nothing")
	}
	walletsMod.Routes(patternCollector(func(pattern string, _ RouteAuth) {
		if _, ok := registered[pattern]; !ok {
			t.Errorf("wallet pattern %q is absent from the router, so the branch gated by WalletRepo "+
				"registered less than walletsModule.Routes() says it serves", pattern)
		}
	}))
}

// patternCollector is a RouteRegistrar that only reports what it was asked to
// register. ⚠️ It exists so that a test can ask a module for its patterns
// instead of restating them.
type patternCollector func(pattern string, auth RouteAuth)

func (c patternCollector) Handle(pattern string, auth RouteAuth, _ http.Handler) { c(pattern, auth) }
