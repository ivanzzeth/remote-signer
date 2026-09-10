package api

import (
	"fmt"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
)

// presetsModule serves the preset catalogue: list, detail, apply and validate.
//
// # Why it is a module (proposal S6, copying S3–S5's shape)
//
// A module is what lets a test drive the *production* route patterns. Routes()
// is exported and RouteRegistrar is an interface, so internal/api/handler's
// external test package (package handler_test — an in-package test cannot
// import internal/api, which imports the handler package) can hand in a
// registrar of its own and get these patterns into a bare http.ServeMux. A mux
// built in a fixture with the patterns typed in by hand is a second source of
// truth that stays green while describing routes the daemon does not serve.
//
// ⚠️ Like the signers and settings modules it is handed an already-constructed
// handler: NewPresetHandler takes six arguments and four options read off
// Router state (two live setting predicates, the API-key repo, the JS
// evaluator, the Solidity validator, the audit logger). Moving that wiring here
// would move Router internals with it and has no bearing on the route table.
type presetsModule struct {
	h *handler.PresetHandler
}

// NewPresetsModule wraps a constructed preset handler. It errors rather than
// registering routes that would nil-panic on the first request.
func NewPresetsModule(h *handler.PresetHandler) (Module, error) {
	if h == nil {
		return nil, fmt.Errorf("preset handler is required")
	}
	return &presetsModule{h: h}, nil
}

func (m *presetsModule) Name() string { return "presets" }

// Routes registers the preset surface: four endpoints, named (proposal S6).
//
// # What changed and what did not
//
// This used to be three patterns, two of which were method-scoped prefixes
// serving three endpoints between them:
//
//	     /api/v1/presets     (any method)      (PermReadPresets)
//	GET  /api/v1/presets/    (any depth)       (PermReadPresets)
//	POST /api/v1/presets/    (any depth)       (PermApplyPreset)
//
// PresetHandler.ServeHTTP then cut r.URL.EscapedPath() apart, stripped a known
// sub-action suffix ("/apply", "/validate"), and PathUnescape'd the remainder
// into an id. The four routes below are that fan-out, written down.
//
// ⛔ THE VERB HOLE THIS CLOSES IS LIVE, AND IT IS THE SAME SHAPE AS 6d30ba1.
// `GET /api/v1/presets/` matched every path under the prefix, and ServeHTTP's
// three branches each carried a comment asserting "no method check needed: GET
// and POST are registered separately, so the mux has already rejected anything
// else". ⛔ That sentence is the bug — the mux had rejected nothing, because
// both prefixes match every sub-path and the *sub-action* is not part of the
// pattern. Measured against the real registrations at 0866784:
//
//	GET  /api/v1/presets/evm%2Fweth/apply  (with a JSON body)  → reached apply()
//	GET  /api/v1/presets/evm%2Fweth/validate                    → reached validatePreset()
//	POST /api/v1/presets/evm%2Fweth                             → 200, the detail view
//
// The first is the one that matters: apply() creates rule instances, and a GET
// reached it holding only PermReadPresets — PermApplyPreset, which the POST
// pattern declares, was never consulted. (A GET with no body stops at 400
// "invalid request body: EOF", so the request needs a body; curl -X GET -d,
// which is one flag.) With per-method routes there is nothing to guard: an
// apply that is not a POST matches no pattern.
// TestPresetRoutes_ApplyRequiresPost drives that through these very patterns
// and asserts no rule row was written.
//
// ⛔ Permissions are byte for byte what those three patterns declared: the two
// reads keep PermReadPresets, and apply *and validate* keep PermApplyPreset,
// because both were reached through `POST /api/v1/presets/`. ⚠️ Note what that
// means for validate — it is a read-only operation sitting on the apply
// permission, i.e. too strict rather than too loose. Copying it verbatim is
// still the rule: proposal §2.5 records "the decomposition quietly changed a
// permission" as the one semantically irreversible risk in this plan, and that
// applies in both directions. Loosening it is its own PR.
// TestPresetRoutes_RegistersExactlyTheProductionPatterns asserts the pattern
// *and* its authorization for all four.
//
// ⚠️ Client-visible answers that changed, measured on both sides — the before
// column against the old registrations and the old handler, the after column
// against this module beside the real registerAPIFallback. Every one of these
// now dispatches to "/api/v1/", whose answer is
// {"error":"not found: no such API endpoint"} with a credential, 401 without:
//
//	request                                    before                     after
//	GET  /api/v1/presets/                      200 the list               404 JSON (fallback)
//	POST /api/v1/presets/                      405 method not allowed     404 JSON (fallback)
//	POST /api/v1/presets/{id}                  200 the detail             404 JSON (fallback)
//	GET  /api/v1/presets/{id}/apply   +body    the apply ran              404 JSON (fallback)
//	GET  /api/v1/presets/{id}/validate         the validation ran         404 JSON (fallback)
//	GET  /api/v1/presets/{id}/                 200 the detail             404 JSON (fallback)
//	GET  /api/v1/presets/evm/weth (unencoded)  200 the detail             404 JSON (fallback)
//	GET  /api/v1/presets/a/b/c                 404 "preset not found"     404 JSON (fallback)
//	GET  /api/v1/presets/{id}/vars             404 "preset not found"     404 JSON (fallback)
//	POST /api/v1/presets                       405 method not allowed     404 JSON (fallback)
//	HEAD /api/v1/presets                       405 method not allowed     200, empty body
//
// ⚠️ The trailing-slash row is the S4 lesson in the benign direction:
// ServeHTTP ran strings.Trim(rawPath, "/"), so "/presets/{id}/" was forgiven
// and served the detail. Go's mux never strips a trailing slash and {id} does
// not match an empty segment, so it is unmatched now. No client sends it —
// every preset call site in pkg/client, pkg/rs-client, pkg/js-client,
// extension/, web/src, cmd/smoke-test and e2e/ builds the path with no trailing
// slash.
//
// ⚠️ The HEAD row is a *widening* and is stated rather than hidden: Go's mux
// matches HEAD against a GET pattern and net/http drops the body, so HEAD on
// the collection now reaches ListPresets where it used to reach ServeHTTP's
// 405. Both listed endpoints are pure reads. Same thing happened to settings in
// S5.
//
// ⚠️ The /vars row is a dead endpoint two SDKs still call
// (pkg/rs-client/src/presets/presets.rs:25 and the vendored
// remote-signer-client@0.0.5 under pkg/mcp-server). It answered 404 before and
// answers 404 now; only the body changes.
//
// ⭐ %2F, which proposal §2.3 row 2 flagged as the risk in this step: measured,
// and it is a net gain exactly as predicted. Go's ServeMux splits the *escaped*
// path on literal '/' and unescapes each segment afterwards, so "evm%2Fweth"
// stays one segment and PathValue("id") returns "evm/weth" with no
// PathUnescape in the handler. ⛔ And nothing about the signed bytes moves:
// middleware/auth.go signs r.URL.EscapedPath(), which routing does not touch.
// Every preset client percent-encodes (pkg/client and pkg/rs-client escape,
// js-client/extension/web use encodeURIComponent, cmd/smoke-test hard-codes
// %2F), which is why the preset half of this step could land and the template
// half could not — see module_templates.go.
func (m *presetsModule) Routes(reg RouteRegistrar) {
	// ⚠️ Permitted(...) is written out at each call rather than hoisted into a
	// local: cmd/archcheck reads these registrations syntactically, and a
	// variable in the argument slot is a value it cannot resolve — the route
	// gates (route-perm-binding, route-mutating-perm) would silently stop
	// seeing these routes' permission.
	reg.Handle("GET /api/v1/presets", Permitted(middleware.PermReadPresets), http.HandlerFunc(m.h.ListPresets))
	reg.Handle("GET /api/v1/presets/{id}", Permitted(middleware.PermReadPresets), http.HandlerFunc(m.h.GetPreset))
	reg.Handle("POST /api/v1/presets/{id}/apply", Permitted(middleware.PermApplyPreset), http.HandlerFunc(m.h.ApplyPreset))
	reg.Handle("POST /api/v1/presets/{id}/validate", Permitted(middleware.PermApplyPreset), http.HandlerFunc(m.h.ValidatePreset))
}
