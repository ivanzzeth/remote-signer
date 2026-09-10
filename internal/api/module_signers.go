package api

import (
	"fmt"
	"net/http"

	evmhandler "github.com/ivanzzeth/remote-signer/internal/api/handler/evm"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
)

// signersModule serves signer management: the collection, the per-signer item,
// the four state-changing actions and the access-grant sub-tree.
//
// # Why it is a module (proposal S4, copying S3's shape)
//
// A module is what lets a test drive the *production* route patterns. Routes()
// is exported and RouteRegistrar is an interface, so internal/api/handler/evm's
// external test package (package evm_test — an in-package test cannot import
// internal/api, which imports the handler package) can hand in a registrar of
// its own and get these patterns into a bare http.ServeMux. A mux built in a
// fixture with the patterns typed in by hand is a second source of truth that
// stays green while describing routes the daemon does not serve.
//
// ⚠️ Like hdWalletsModule and apiKeysModule, and unlike walletsModule, it is
// handed an already-constructed handler. NewSignerHandler takes a live
// read-only predicate and is then fed a signer repo, a wallet repo, an audit
// logger and a live per-key keystore limit, all five read off Router state;
// moving that wiring here would move five Router internals with it and has no
// bearing on the route table. This step's claim is only that the eleven
// endpoints below serve what the seven patterns did.
type signersModule struct {
	h *evmhandler.SignerHandler
}

// NewSignersModule wraps a constructed signer handler. It errors rather than
// registering routes that would nil-panic on the first request.
func NewSignersModule(h *evmhandler.SignerHandler) (Module, error) {
	if h == nil {
		return nil, fmt.Errorf("signer handler is required")
	}
	return &signersModule{h: h}, nil
}

func (m *signersModule) Name() string { return "signers" }

// Routes registers the signer surface: eleven endpoints, named (proposal S4).
//
// # What changed and what did not
//
// This used to be seven patterns, one of them a method-less prefix that carried
// five endpoints:
//
//	GET  /api/v1/evm/signers                            (PermReadSigners)
//	POST /api/v1/evm/signers                            (PermCreateSigners)
//	POST /api/v1/evm/signers/{address}/unlock           (PermReadSigners)
//	POST /api/v1/evm/signers/{address}/lock             (PermReadSigners)
//	POST /api/v1/evm/signers/{address}/approve          (PermReadSigners)
//	POST /api/v1/evm/signers/{address}/transfer         (PermReadSigners)
//	     /api/v1/evm/signers/    (any method, any depth) (PermReadSigners)
//
// ⛔ THIS IS THE STRUCTURAL FIX FOR 6d30ba1. The last pattern was registered
// with no method, so it matched every verb. Go's ServeMux answers 405 only when
// a pattern matches the path and *no* pattern matches the method — with a
// method-less prefix in the table there is always a match, so 405 never
// happened and `GET /api/v1/evm/signers/{address}/unlock` and
// `DELETE .../{address}/approve` fell through to HandleSignerAction, which read
// the action out of the path and performed it, on a daemon holding private
// keys. 6d30ba1 stopped that with an explicit method guard inside the handler.
// With the prefix gone, an unroutable verb reaches no handler at all: the four
// actions are POST-only patterns, so the mux itself answers 405 before any
// handler runs. TestSignerRoutes_StateChangeRequiresPost drives that through
// these very patterns and asserts the signer manager was never called.
//
// ⛔ Permissions are byte for byte what those seven patterns declared, and the
// five endpoints that were hiding behind the prefix inherit the prefix's
// PermReadSigners unchanged. Decomposition *creates* the opportunity to give
// each endpoint the permission it deserves — ⚠️ four of the new rows are
// mutating endpoints on a read permission, and they are added to
// scripts/lib/arch-baseline/ast/route-mutating-perm.txt as newly *visible*
// pre-existing debt, the same shape as the four unlock/lock/approve/transfer
// rows already there. Changing them is a security decision, not a refactor, and
// proposal §2.5 records "the decomposition quietly changed a permission" as the
// one semantically irreversible risk in this plan: too strict shows up in e2e,
// too loose does not. TestSignerRoutes_RegistersExactlyTheProductionPatterns
// asserts the pattern *and* its authorization for all eleven.
//
// ⚠️ Client-visible answers that changed. Both columns are *measured* — the
// before column against the old registrations and the old handler, the after
// column against this module next to the real registerAPIFallback — not read
// off the code. Every one of these paths now dispatches to "/api/v1/", whose
// answer is {"error":"not found: no such API endpoint"} with a credential and
// 401 without one:
//
//	request                                       before (measured at 6d30ba1)      after
//	GET    /api/v1/evm/signers/{addr}/unlock      405 "method not allowed"          404 JSON (fallback)
//	GET    /api/v1/evm/signers/{addr}/lock        405 "method not allowed"          404 JSON (fallback)
//	DELETE /api/v1/evm/signers/{addr}/approve     405 "method not allowed"          404 JSON (fallback)
//	PATCH  /api/v1/evm/signers/{addr}/transfer    405 "method not allowed"          404 JSON (fallback)
//	GET    /api/v1/evm/signers/                   400 "invalid path: expected …"    404 JSON (fallback)
//	POST   /api/v1/evm/signers/{addr}/foobar      400 "unknown action: foobar"      404 JSON (fallback)
//	GET    /api/v1/evm/signers/{addr}             400 "invalid path: expected …"    404 JSON (fallback)
//	DELETE /api/v1/evm/signers/{addr}/access      400 "api_key_id is required …"    404 JSON (fallback)
//	GET    /api/v1/evm/signers/{addr}/access/a/b  200 the access list               404 JSON (fallback)
//	DELETE /api/v1/evm/signers/{addr}/            204, and the signer was deleted   404 JSON (fallback)
//	PATCH  /api/v1/evm/signers/{addr}/            200, and the labels were patched  404 JSON (fallback)
//	PUT    /api/v1/evm/signers                    301 → /api/v1/evm/signers/        404 JSON (fallback)
//
// ⛔ The first four rows answered 405 only because 6d30ba1 put a
// signerActionMethods guard inside the handler eight commits ago. Before that
// they were 200 and the action happened: the unlock ran, the approval ran, the
// ownership transfer ran. That is the defect this decomposition closes
// structurally — the guard is gone from signer.go because there is no longer a
// pattern that routes those verbs anywhere.
//
// ⚠️ Row 9 is worth reading twice: SplitN(path, "/", 3) put "a/b" in the third
// part, and handleAccess's GET branch ignored it, so a path two segments deeper
// than any endpoint returned a signer's access list.
//
// ⚠️ Trailing slash (rows 10-11): unlike the HD wallet handler, signer.go never
// ran TrimSuffix(path, "/") — the empty last segment simply became an empty
// *action*, and the action-less branch runs for DELETE and PATCH. So a trailing
// slash did not merely get forgiven, it selected the item endpoints:
// `DELETE .../{addr}/` deleted the signer. Go's mux never strips a trailing
// slash and {address} does not match an empty segment, so these are unmatched
// now. ⛔ The repo's own SDKs never send that shape (pkg/client/evm builds every
// signer path with fmt.Sprintf and no trailing slash), but a hand-written client
// that did would break.
//
// ⚠️ Row 12 is not a 405 becoming a 404: it was a **301 redirect**. ServeMux
// redirects a path with no match to the subtree pattern one level up, and
// "/api/v1/evm/signers/" was such a pattern, so PUT on the collection was bounced
// into the prefix — where HandleSignerAction then answered 400. With the prefix
// gone there is nothing to redirect to.
//
// ⚠️ These are proposal §0 correction 9 arriving for real, and note they are NOT
// what a bare test mux answers: with no "/api/v1/" in the way the mux answers its
// own 404, or 405 where a sibling method is registered on the same path. The
// handler package's route tests assert whichever of the two actually applies
// there; internal/api's TestAPIFallback_SignerStrandedPaths asserts the daemon's.
//
// ⛔ Do not "fix" any of these by adding "/api/v1/evm/signers/" back. That is
// the pattern this step exists to remove, and re-adding it re-opens the verb
// hole in exactly the form 6d30ba1 found it.
func (m *signersModule) Routes(reg RouteRegistrar) {
	// ⚠️ Permitted(...) is written out at each call rather than hoisted into a
	// local: cmd/archcheck reads these registrations syntactically, and a
	// variable in the argument slot is a value it cannot resolve — the route
	// gates (route-perm-binding, route-mutating-perm) would silently stop
	// seeing these routes' permission.
	reg.Handle("GET /api/v1/evm/signers", Permitted(middleware.PermReadSigners), http.HandlerFunc(m.h.ListSigners))
	reg.Handle("POST /api/v1/evm/signers", Permitted(middleware.PermCreateSigners), http.HandlerFunc(m.h.CreateSigner))
	reg.Handle("DELETE /api/v1/evm/signers/{address}", Permitted(middleware.PermReadSigners), http.HandlerFunc(m.h.DeleteSigner))
	reg.Handle("PATCH /api/v1/evm/signers/{address}", Permitted(middleware.PermReadSigners), http.HandlerFunc(m.h.PatchSignerLabels))
	reg.Handle("POST /api/v1/evm/signers/{address}/unlock", Permitted(middleware.PermReadSigners), http.HandlerFunc(m.h.Unlock))
	reg.Handle("POST /api/v1/evm/signers/{address}/lock", Permitted(middleware.PermReadSigners), http.HandlerFunc(m.h.Lock))
	reg.Handle("POST /api/v1/evm/signers/{address}/approve", Permitted(middleware.PermReadSigners), http.HandlerFunc(m.h.ApproveSigner))
	reg.Handle("POST /api/v1/evm/signers/{address}/transfer", Permitted(middleware.PermReadSigners), http.HandlerFunc(m.h.TransferOwnership))
	reg.Handle("GET /api/v1/evm/signers/{address}/access", Permitted(middleware.PermReadSigners), http.HandlerFunc(m.h.ListAccess))
	reg.Handle("POST /api/v1/evm/signers/{address}/access", Permitted(middleware.PermReadSigners), http.HandlerFunc(m.h.GrantAccess))
	reg.Handle("DELETE /api/v1/evm/signers/{address}/access/{keyID}", Permitted(middleware.PermReadSigners), http.HandlerFunc(m.h.RevokeAccess))
}
