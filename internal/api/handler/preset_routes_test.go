//go:build integration

// Package handler_test — this file holds the preset handler's route-level tests.
//
// # Why these live in an external test package (proposal §2.4, steps S2/S6)
//
// S6 splits PresetHandler into one function per method and sub-path and moves
// it onto r.PathValue; ServeHTTP is gone. The questions below are about which
// request reaches which of those functions, and after the split that is decided
// by internal/api's route registration — so answering them means going through
// it.
//
// ⛔ The tempting way — build an http.ServeMux in the fixture and register
// "/api/v1/presets" and friends by hand — creates a second source of truth for
// the route table. It drifts from the production registration silently: the
// tests stay green while exercising routes the daemon does not serve. So the
// patterns come from api.presetsModule's Routes(), reached through the exported
// api.Module / api.RouteRegistrar pair, and no pattern is written down here
// except in the one test whose subject *is* the pattern list.
//
// ⚠️ Which is why this is `package handler_test`: internal/api imports
// internal/api/handler, so an in-package test file cannot import internal/api
// back — that is an import cycle. The cost is exported identifiers only, which
// costs nothing here: the fixture is built from storage's Gorm repositories and
// the handler's own exported constructor.
//
// ⚠️ `//go:build integration` because the fixture is a real SQLite database,
// the same tier every other preset test in this package sits in (TESTING.md:
// the tag says what a test may touch).
//
// ⚠️ What these tests do NOT exercise: the middleware chain. All four routes
// register as Permitted(...), whose chain begins with AuthMiddleware, which
// refuses any request lacking X-API-Key-ID / X-Timestamp / X-Signature. These
// tests inject an API key through the request context instead, as the preset
// family always has. So the test registrar drops the RouteAuth it is handed and
// registers the bare handler: what is under test is dispatch. ⛔ Do not read a
// green run here as evidence that a preset route is correctly permissioned —
// that lives in the archcheck route-auth gates and their baselines, and in the
// pattern assertion below.
//
// ⚠️ The mux these tests build has no /api/v1/ fallback in it, so an unclaimed
// path gets the *mux's* own 404 and a wrong verb on a claimed path gets the
// mux's own 405. A daemon answers differently — "/api/v1/" matches every path
// and every method, so both land on the JSON 404 fallback. That difference is
// measured in module_presets.go's table.
package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/api"
	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------- the registrar ----------
//
// ⚠️ Named preset* rather than reusing the wallet / api-key / settings /
// template families' registrars: they all live in this same external package,
// so a shared name would be a redeclaration. Same shape, different name.

type presetMuxRegistrar struct{ mux *http.ServeMux }

func (m presetMuxRegistrar) Handle(pattern string, _ api.RouteAuth, h http.Handler) {
	m.mux.Handle(pattern, h)
}

type presetRecordingRegistrar struct {
	record func(pattern string, auth api.RouteAuth)
}

func (r presetRecordingRegistrar) Handle(pattern string, auth api.RouteAuth, _ http.Handler) {
	r.record(pattern, auth)
}

// ⭐ The id is the shape that matters in this step: a v0.3 preset id is a file
// stem containing a slash, and it reaches the daemon percent-encoded.
const (
	presetRouteID      = "evm/weth"
	presetRouteEncoded = "evm%2Fweth"
)

// presetRouteEnv is a preset handler over a real (in-memory) database, wired so
// that apply actually creates rule rows — which is what makes
// TestPresetRoutes_ApplyRequiresPost's negative assertion mean something.
type presetRouteEnv struct {
	h        *handler.PresetHandler
	ruleRepo storage.RuleRepository
}

func newPresetRouteEnv(t *testing.T) *presetRouteEnv {
	t.Helper()
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}, &types.Rule{}, &types.RuleBudget{}))

	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)
	ruleRepo, err := storage.NewGormRuleRepository(db)
	require.NoError(t, err)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	svc, err := service.NewTemplateService(tmplRepo, ruleRepo, budgetRepo, lg)
	require.NoError(t, err)
	eval, err := evm.NewJSRuleEvaluator(lg)
	require.NoError(t, err)

	require.NoError(t, tmplRepo.Create(context.Background(), &types.RuleTemplate{
		ID: "evm/weth_tmpl", Name: "WETH template", Type: types.RuleTypeSignTypeRestriction,
		Mode: types.RuleModeWhitelist, ChainType: types.ChainTypeEVM,
		Source: types.RuleSourceFile, ContentHash: "h", Enabled: true,
		Config:    []byte(`{"allowed_sign_types":["transaction"]}`),
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}))
	require.NoError(t, presetRepo.Create(context.Background(), &types.RulePreset{
		ID: presetRouteID, Name: "WETH", ChainType: types.ChainTypeEVM, ChainID: "1",
		TemplateIDs: []byte(`["evm/weth_tmpl"]`), Enabled: true,
		Source: types.RuleSourceFile, ContentHash: "h",
	}))

	h, err := handler.NewPresetHandler(presetRepo, tmplRepo, db, svc, nil, lg, handler.WithPresetJSEvaluator(eval))
	require.NoError(t, err)
	return &presetRouteEnv{h: h, ruleRepo: ruleRepo}
}

// instanceCount is apply's observable effect: one rule row per template_id.
func (e *presetRouteEnv) instanceCount(t *testing.T) int {
	t.Helper()
	rows, err := e.ruleRepo.List(context.Background(), storage.RuleFilter{})
	require.NoError(t, err)
	return len(rows)
}

// presetMux registers the production preset routes over an otherwise empty mux.
//
// ⭐ An empty mux is deliberate: a path no preset pattern claims must reach
// nothing at all, which is exactly the property the two method-scoped prefixes
// could not have — they matched every sub-path, sub-action included.
func presetMux(t *testing.T, h *handler.PresetHandler) http.Handler {
	t.Helper()
	mod, err := api.NewPresetsModule(h)
	require.NoError(t, err)
	require.NotNil(t, mod, "no module means no pattern would be registered, and every request below "+
		"would 404 for a reason that has nothing to do with what is under test")
	mux := http.NewServeMux()
	mod.Routes(presetMuxRegistrar{mux: mux})
	return mux
}

func presetRouteAdminKey() *types.APIKey {
	return &types.APIKey{ID: "admin-key", Name: "Admin", Role: types.RoleAdmin, Enabled: true}
}

func doPresetRouteRequest(t *testing.T, mux http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, presetRouteAdminKey()))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestPresetRoutes_RegistersExactlyTheProductionPatterns is the assertion that
// keeps a decomposition from quietly changing authorization.
//
// ⛔ It asserts the pattern *and* its RouteAuth for all four. Every permission
// is copied from the three patterns these replaced — the two reads from
// `/api/v1/presets` and `GET /api/v1/presets/`, apply *and validate* from
// `POST /api/v1/presets/`. This test and route-perm-binding are the only two
// things that would notice a change. Negatively verified: loosening validate to
// PermReadPresets reddens both.
func TestPresetRoutes_RegistersExactlyTheProductionPatterns(t *testing.T) {
	env := newPresetRouteEnv(t)
	mod, err := api.NewPresetsModule(env.h)
	require.NoError(t, err)

	got := map[string]string{}
	mod.Routes(presetRecordingRegistrar{record: func(pattern string, auth api.RouteAuth) {
		got[pattern] = auth.String()
	}})

	assert.Equal(t, map[string]string{
		"GET /api/v1/presets":                "permitted(read_presets)",
		"GET /api/v1/presets/{id}":           "permitted(read_presets)",
		"POST /api/v1/presets/{id}/apply":    "permitted(apply_preset)",
		"POST /api/v1/presets/{id}/validate": "permitted(apply_preset)",
	}, got)
	assert.Equal(t, "presets", mod.Name())
}

// TestPresetRoutes_EncodedSlashID pins the thing proposal §2.3 row 2 flagged as
// this step's risk, in the direction the measurement actually found.
//
// ⭐ A percent-encoded slash survives as ONE wildcard segment and PathValue
// hands the handler the decoded id — so the handler needs no PathUnescape, and
// `GET /api/v1/presets/evm%2Fweth` reaches the detail of preset "evm/weth".
// ⛔ The unencoded form is deliberately not routed: it is what makes the path
// ambiguous, and no preset client sends it.
func TestPresetRoutes_EncodedSlashID(t *testing.T) {
	env := newPresetRouteEnv(t)
	mux := presetMux(t, env.h)

	rr := doPresetRouteRequest(t, mux, http.MethodGet, "/api/v1/presets/"+presetRouteEncoded, "")
	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, presetRouteID, resp["id"],
		"the id must arrive decoded — an %%2F that reached the repository as literal text would 404")

	// The unencoded form, stated as a fact of this design rather than left to be
	// discovered. ⚠️ It is why the *template* half of S6 could not land; see
	// module_templates.go.
	raw := doPresetRouteRequest(t, mux, http.MethodGet, "/api/v1/presets/evm/weth", "")
	assert.Equal(t, http.StatusNotFound, raw.Code,
		"an id spelled with a literal slash spans two segments and no route claims it")
}

// TestPresetRoutes_ApplyRequiresPost is the reason this step is not only
// tidying. ⛔ Before it, `GET /api/v1/presets/` matched every path under the
// prefix including "/{id}/apply", and ServeHTTP dispatched on the suffix with
// no method check — so a GET carrying a JSON body applied the preset while
// holding only read_presets. Measured at 0866784: 201 Created, one rule row
// written.
//
// ⭐ The assertion is on the row count, not the status: a handler that applied
// and then wrote 405 would satisfy a status-only check. The POST arm is the
// positive control — without it a green refusal could mean the fixture was
// incapable of applying anything.
func TestPresetRoutes_ApplyRequiresPost(t *testing.T) {
	const body = `{"variables":{}}`
	path := "/api/v1/presets/" + presetRouteEncoded + "/apply"

	t.Run("POST applies", func(t *testing.T) {
		env := newPresetRouteEnv(t)
		mux := presetMux(t, env.h)
		require.Equal(t, 0, env.instanceCount(t))

		rr := doPresetRouteRequest(t, mux, http.MethodPost, path, body)
		require.Equal(t, http.StatusCreated, rr.Code, "body: %s", rr.Body.String())
		assert.Equal(t, 1, env.instanceCount(t), "the positive control really did write a rule")
	})

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead} {
		t.Run(method+" cannot apply", func(t *testing.T) {
			env := newPresetRouteEnv(t)
			mux := presetMux(t, env.h)

			rr := doPresetRouteRequest(t, mux, method, path, body)
			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code,
				"the bare mux answers 405 because POST is registered on this path; a daemon answers "+
					"the /api/v1/ fallback's 404 — see module_presets.go")
			assert.Equal(t, 0, env.instanceCount(t),
				"⛔ %s must not apply the preset — this is the assertion that matters, not the status", method)
		})
	}
}

// TestPresetRoutes_ValidateRequiresPost is the same shape for the other
// sub-action. Validation is read-only, so the damage was smaller, but it was
// reachable on read_presets by the identical route hole.
func TestPresetRoutes_ValidateRequiresPost(t *testing.T) {
	env := newPresetRouteEnv(t)
	mux := presetMux(t, env.h)
	path := "/api/v1/presets/" + presetRouteEncoded + "/validate"

	ok := doPresetRouteRequest(t, mux, http.MethodPost, path, `{}`)
	require.Equal(t, http.StatusOK, ok.Code, "positive control; body: %s", ok.Body.String())

	refused := doPresetRouteRequest(t, mux, http.MethodGet, path, "")
	assert.Equal(t, http.StatusMethodNotAllowed, refused.Code)
}

// TestPresetRoutes_CollectionRejectsWrongMethod replaces
// TestPresetHandler_Routing_RejectsWrongMethod, which asserted ServeHTTP's own
// 405 on POST /api/v1/presets.
//
// ⚠️ HEAD is called out separately because it is a *widening*: Go's mux matches
// HEAD against a GET pattern and net/http drops the body, so HEAD now reaches
// ListPresets where ServeHTTP used to answer 405. The collection is a pure
// read, and this is what HTTP prescribes — the same widening S5 recorded for
// settings — but it is a change, so it is pinned rather than left implicit.
func TestPresetRoutes_CollectionRejectsWrongMethod(t *testing.T) {
	env := newPresetRouteEnv(t)
	mux := presetMux(t, env.h)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rr := doPresetRouteRequest(t, mux, method, "/api/v1/presets", "")
		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code, "%s on the collection", method)
	}

	head := doPresetRouteRequest(t, mux, http.MethodHead, "/api/v1/presets", "")
	assert.Equal(t, http.StatusOK, head.Code, "⚠️ widening: HEAD now reaches the GET route")
}

// TestPresetRoutes_UnclaimedPathNoLongerReachesTheHandler replaces
// TestPresetHandler_ServeHTTP_UnknownSubAction. Each path below was swallowed
// by a prefix pattern and turned into an id; none of them is a preset endpoint.
//
// ⭐ The control arm is what makes it evidence rather than a tautology: the same
// handler, called directly with the id filled in, answers. So the 404 comes
// from routing and not from a broken fixture.
func TestPresetRoutes_UnclaimedPathNoLongerReachesTheHandler(t *testing.T) {
	for _, tc := range []struct{ name, path string }{
		{"unknown sub-action", "/api/v1/presets/" + presetRouteEncoded + "/something"},
		{"deep path", "/api/v1/presets/a/b/c"},
		{"trailing slash on the item", "/api/v1/presets/" + presetRouteEncoded + "/"},
		{"prefix with no id", "/api/v1/presets/"},
		{"dead /vars endpoint two SDKs still call", "/api/v1/presets/" + presetRouteEncoded + "/vars"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newPresetRouteEnv(t)
			mux := presetMux(t, env.h)

			rr := doPresetRouteRequest(t, mux, http.MethodGet, tc.path, "")
			assert.Equal(t, http.StatusNotFound, rr.Code, "no preset route claims %s", tc.path)

			direct := httptest.NewRequest(http.MethodGet, "/api/v1/presets/"+presetRouteEncoded, nil)
			direct.SetPathValue("id", presetRouteID)
			direct = direct.WithContext(context.WithValue(direct.Context(),
				middleware.APIKeyContextKey, presetRouteAdminKey()))
			rec := httptest.NewRecorder()
			env.h.GetPreset(rec, direct)
			require.Equal(t, http.StatusOK, rec.Code, "control arm: the handler does answer when a route reaches it")
		})
	}
}
