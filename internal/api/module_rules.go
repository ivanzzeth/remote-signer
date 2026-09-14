package api

import (
	"fmt"
	"net/http"

	evmhandler "github.com/ivanzzeth/remote-signer/internal/api/handler/evm"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
)

// rulesModule serves the rule-management surface.
//
// # Why it is a module (proposal S8, copying S3–S7's shape)
//
// A module is what lets a test drive the *production* route patterns. Routes()
// is exported and RouteRegistrar is an interface, so internal/api/handler/evm's
// external test package (package evm_test — an in-package test cannot import
// internal/api, which imports the handler package) can hand in a registrar of
// its own and get these patterns into a bare http.ServeMux. A mux built in a
// fixture with the patterns typed in by hand is a second source of truth that
// stays green while describing routes the daemon does not serve.
//
// ⚠️ Like the signers, settings, presets, templates and requests modules it is
// handed an already-constructed handler: NewRuleHandler takes up to ten options
// read off Router state (a live read-only predicate, a live per-key rule limit,
// a live approval switch, four repositories, two validators and a callback into
// the sign service). Moving that wiring here would move Router internals with it
// and has no bearing on the route table.
//
// # ⛔ Where this module is, in the middle of S8
//
// rule.go's ServeHTTP was one method-less prefix pair serving twelve endpoints,
// the largest single entry in the handler-path-dispatch baseline after settings.
// S8 moved them in three slices — the three approval-state actions, then the
// four guarded sub-resources (two validate, two budget), then the collection and
// the item together with the prefixes themselves — and this is the finished
// state: **twelve named routes, ServeHTTP deleted**.
//
// ⛔ The order was not arbitrary. Removing the method-less `/api/v1/evm/rules`
// registration while `/api/v1/evm/rules/` was still registered makes Go's mux
// answer **301, redirecting to the trailing-slash form**, for every verb the new
// method-scoped patterns do not claim (measured: PUT and DELETE on the
// collection go 405 → 301). So the collection and the prefix had to go in the
// same slice, and they went last.
type rulesModule struct {
	h *evmhandler.RuleHandler

	// withBudgets mirrors the condition the two budget branches of ServeHTTP
	// carried (`h.budgetRepo != nil`). ⚠️ It is a production variable, not a test
	// knob: setupRoutes passes WithBudgetRepo only when RouterConfig.BudgetRepo
	// is set, and e2e/test_server.go is one configuration that does set it while
	// others do not.
	withBudgets bool
}

// NewRulesModule wraps a constructed rule handler. It errors rather than
// registering routes that would nil-panic on the first request.
//
// ⚠️ withBudgets must be the same condition setupRoutes used to build the
// handler's budget repository. ⛔ Registering the two budget routes
// unconditionally and answering from inside would put routes in the table that
// a daemon without a budget repository does not serve — the same "reading
// setupRoutes cannot tell you what is served" problem the module shape exists
// to remove — and it would also change the answer: with no budget repository
// ResetBudgets answers its own 500 ("budget repository not configured"), which
// no deployment has ever seen, because the ServeHTTP branch in front of it
// required the repository to be there.
func NewRulesModule(h *evmhandler.RuleHandler, withBudgets bool) (Module, error) {
	if h == nil {
		return nil, fmt.Errorf("rule handler is required")
	}
	return &rulesModule{h: h, withBudgets: withBudgets}, nil
}

func (m *rulesModule) Name() string { return "rules" }

// Routes registers the rule endpoints this slice has named.
//
// # ⛔ Permissions: six of the eight writes moved off list_rules
//
// Eleven of the twelve used to carry PermListRules, because that is what the two
// prefixes they came out of declared — route_auth.go's ⛔ KNOWN LIMIT section
// said for as long as it existed that the prefix "declares PermListRules for all
// twelve endpoints behind it". Naming them turned that sentence into eight rows
// of route-mutating-perm.txt: eight mutating routes gated on a read permission.
//
// ⭐ 2026-09-14, slice 3 of the RBAC-gap PR, resolved those eight one at a time
// rather than as a batch, because they are not one question:
//
//	POST   /rules            → create_rule_self   (same roles; declares the truth)
//	PATCH  /rules/{id}       → modify_own_rule    (same roles)
//	DELETE /rules/{id}       → delete_own_rule    (same roles)
//	POST   /rules/{id}/approve → approve_rule     ⭐ narrows to admin
//	POST   /rules/{id}/reject  → approve_rule     ⭐ narrows to admin
//	POST   /rules/{id}/propose → propose_rule     (same roles)
//	POST   /rules/validate      ⛔ LEFT on list_rules — read-only POST
//	POST   /rules/{id}/validate ⛔ LEFT on list_rules — read-only POST
//
// ⚠️ Only approve and reject change anyone's access, and only on paper: the
// handler already refused every non-admin, and four e2e tests have asserted that
// for dev and agent all along. ⛔ The other four moves are no-ops in role terms
// (verified against rbac.go's grant maps, not guessed from the names) and are
// worth making anyway — a route that declares "may look at rules" as the price
// of deleting one is wrong even when today's grants happen to coincide.
//
// ⚠️ The twelfth, POST .../{id}/budgets/reset, keeps the PermManageBudgets it
// already had as a separately registered route.
//
// ⚠️ Every one of these still has a handler check that is strictly narrower, and
// none of them could be replaced by a route permission: approve/reject/propose
// and both validates test a *role*, and create/update/delete test ownership and
// source per row. RouteAuth expresses neither. ⛔ The route is the outer door,
// and the point of this slice is that the outer door now says what it guards.
//
// # Behaviour, measured before and after
//
// ⭐ The measurement that matters most here is a negative one, and it is the
// opposite of what S4, S6 and S7 found. rule.go has a guard the other handlers
// lacked — `ruleID != "" && !strings.Contains(ruleID, "/")` on every sub-action
// branch — and it closes both of the holes the earlier steps hit:
//
//	request                                          before                        after
//	GET    /api/v1/evm/rules/{id}/approve            400 invalid rule_id format    400 (unchanged, still the prefix)
//	DELETE /api/v1/evm/rules/{id}/approve            400 invalid rule_id format    400 (unchanged)
//	PUT    /api/v1/evm/rules/{id}/approve            400 invalid rule_id format    400 (unchanged)
//	POST   /api/v1/evm/rules/a/{id}/approve          400 invalid rule_id format    400 (unchanged)
//	POST   /api/v1/evm/rules/a/b/c/{id}/approve      400 invalid rule_id format    400 (unchanged)
//	POST   /api/v1/evm/rules/approve                 405 method not allowed        405 (unchanged)
//	POST   /api/v1/evm/rules/{id}/approve/           400 invalid rule_id format    400 (unchanged)
//	POST   /api/v1/evm/rules/{id}/approve            200, approved {id}            200, approved {id}
//	POST   /api/v1/evm/rules/a%2Fb/approve           400 invalid rule_id format    404 rule not found
//
// And the collection/item half, which is where every client-visible change is:
//
//	request                                          before                        after
//	POST   /api/v1/evm/rules/           ⛔            201, CREATED A RULE           404 JSON (fallback)
//	DELETE /api/v1/evm/rules/{id}/      ⛔            204, DELETED THE ROW          404 JSON (fallback)
//	GET    /api/v1/evm/rules/                        200, listed                   404 JSON (fallback)
//	GET    /api/v1/evm/rules/{id}/                   200, read the rule            404 JSON (fallback)
//	GET    /api/v1/evm/rules/a/b/c/d                 400 invalid rule_id format    404 JSON (fallback)
//	PUT    /api/v1/evm/rules                         405 method not allowed        404 JSON (fallback)
//	DELETE /api/v1/evm/rules                         405 method not allowed        404 JSON (fallback)
//	PUT    /api/v1/evm/rules/{id}                    405 method not allowed        404 JSON (fallback)
//	POST   /api/v1/evm/rules/{id}                    405 method not allowed        404 JSON (fallback)
//	GET    /api/v1/evm/rules/{id}/budgets, no repo   400 invalid rule_id format    404 JSON (fallback)
//	POST   .../{id}/budgets/reset, no repo           400 invalid rule_id format    404 JSON (fallback)
//	HEAD   /api/v1/evm/rules                         405 method not allowed        200, empty body
//	HEAD   /api/v1/evm/rules/{id}                    405 method not allowed        200, empty body
//	GET    /api/v1/evm/rules/validate                404 rule not found            404 rule not found
//
// ⛔ The first two rows are the defect this step closes, and they are the only
// rows in the whole surface where the *before* answer was a successful mutation
// reached by a shape nobody wrote down. ServeHTTP trimmed "/api/v1/evm/rules"
// and then trimmed the leading "/", so an empty remainder meant **the
// collection** — which made `POST /api/v1/evm/rules/` a create. The item form
// trimmed to a clean id, which made `DELETE /api/v1/evm/rules/{id}/` a delete.
// ⚠️ Proposal lesson 3's "trailing slash cuts both ways", in the direction that
// mutates: the same shape as `DELETE /signers/{addr}/` and `POST /templates/`.
// Go's mux never strips a trailing slash, so none of these match a pattern now.
//
// ⚠️ Rows 3–5 are the same forgiveness on the read side — wrong answers rather
// than wrong mutations. ⛔ Row 5 is the one proposal §2.3 row 1 was about, and
// the answer it worried about is unchanged: it is still JSON, not the SPA's
// HTML, because S1② put the /api/v1/ fallback there. Only the message moved,
// from "invalid rule_id format" to "not found: no such API endpoint".
//
// ⚠️ Rows 6–11 are status changes, not holes: ServeHTTP checked its method and
// answered 405, or refused the reconstructed id with a 400, before doing
// anything. ⭐ Rows 12–13 are a *widening*, stated rather than hidden: Go's mux
// matches HEAD against a GET pattern and net/http drops the body, so HEAD now
// reaches a read endpoint. Both are pure reads, and the same thing happened to
// settings in S5 and to templates, presets and requests in S6/S7.
//
// ⚠️ Row 14 is deliberately in the table as an *unchanged* row: "validate" is a
// legal single segment, so a GET on it matches GET /api/v1/evm/rules/{id} and
// reads a rule with that id — exactly what ServeHTTP's fallthrough did with it.
// ⭐ It is also the one pattern overlap here (the literal is a strict subset of
// the wildcard, §2.2's safe shape, not the panicking one).
//
// ⛔ There is no verb hole here and no depth swallow, and both were probed the
// way the earlier steps' were — against the three real registrations, with the
// repository's rows read back after every request rather than the status. A
// wrong verb on /approve did not approve anything: the branch required
// `r.Method == http.MethodPost`, and every shape it refused fell through to a
// 400. `POST /api/v1/evm/rules/a/{id}/approve` did not approve {id} either,
// which is precisely the request that approved the wrong row on
// /api/v1/evm/requests in S7 — there the id was read as "the segment before the
// action", here the branch refuses any id containing a '/'. ⭐ S8's twelve
// endpoints are the finest-grained in the repo (proposal §2.5), and on this
// evidence that is why.
//
// ⚠️ The last row is the only answer that changes in this slice, and no client
// can send it: a rule id is matched by ruleIDPattern (rule.go), which admits
// `rule_<uuid>`, `cfg_<hex>` and `[a-zA-Z0-9][0-9A-Za-z_-]{0,63}` — none of
// which contains '/' — plus the synthetic `sim:0x…` form, which does not
// either. So an id needing percent-encoding cannot exist, and the template
// trap that blocked S6 for a step has no counterpart here. ⛔ Checked in
// pkg/client, pkg/rs-client, pkg/js-client, extension/background.js, web/src,
// pkg/mcp-server and e2e/, not assumed.
func (m *rulesModule) Routes(reg RouteRegistrar) {
	// ⚠️ Permitted(...) is written out at each call rather than hoisted into a
	// local: cmd/archcheck reads these registrations syntactically, and a
	// variable in the argument slot is a value it cannot resolve — the route
	// gates (route-perm-binding, route-auth-exempt, route-mutating-perm) would
	// silently stop seeing these routes.
	// ---------- the collection and the item ----------
	//
	// ⛔ The two reads keep PermListRules. The three writes do NOT: 2026-09-14
	// gave each the permission that names what it does.
	//
	// ⚠️ These three are a **no-op in role terms today, and that is the point**:
	// create_rule_self, modify_own_rule and delete_own_rule are granted to
	// exactly the same set as list_rules (admin, dev, agent — never strategy),
	// so nobody's access changes. What changes is that the route now declares the
	// truth, so a future role granted list_rules without create_rule_self is
	// actually refused instead of silently able to create rules. ⛔ Verified
	// against rbac.go's grant maps, not inferred from the names.
	//
	// ⚠️ Each is additionally resource-scoped inside the handler — createRule
	// forces applied_to=self for non-admin, updateRule and deleteRule refuse a
	// row this key does not own and refuse config-sourced rules outright — and
	// that is still the check that matters. The route is the outer door.
	reg.Handle("GET /api/v1/evm/rules", Permitted(middleware.PermListRules), http.HandlerFunc(m.h.ListRules))
	reg.Handle("POST /api/v1/evm/rules", Permitted(middleware.PermCreateRuleSelf), http.HandlerFunc(m.h.CreateRule))
	reg.Handle("GET /api/v1/evm/rules/{id}", Permitted(middleware.PermListRules), http.HandlerFunc(m.h.GetRule))
	reg.Handle("PATCH /api/v1/evm/rules/{id}", Permitted(middleware.PermModifyOwnRule), http.HandlerFunc(m.h.UpdateRule))
	reg.Handle("DELETE /api/v1/evm/rules/{id}", Permitted(middleware.PermDeleteOwnRule), http.HandlerFunc(m.h.DeleteRule))

	// ---------- the three approval-state actions ----------
	//
	// ⭐ approve and reject are the one place in this module where the role set
	// really narrows: PermApproveRule is granted to **admin alone**, while
	// list_rules is held by admin, dev and agent. ⚠️ No caller loses anything,
	// because rule_query.go:278/344 already refused a non-admin with 403 — and
	// e2e has asserted that for both verbs, for both dev and agent, all along
	// (TestE2E_RuleApproval_RBAC_Approve / _Reject, TestRBAC_A2_Dev A2.11,
	// TestRBAC_A3_Agent A3.24). What moves is *where* the refusal happens.
	//
	// ⛔ And it retires a false comment, the twin of the one router.go carried
	// about templates: rule_query.go:276 said "enforced by RBAC middleware
	// PermApproveRule, but double-check here for defense in depth". The
	// middleware was NOT enforcing it — PermApproveRule was referenced by nothing
	// but that sentence — so the "defense in depth" was the only defense there
	// was. Now the comment is true and the depth is real.
	//
	// ⚠️ propose takes PermProposeRule, which is granted to the same three roles
	// as list_rules, so it changes no access either. The handler's agent-or-admin
	// test stays: it is a *role* check and narrower than the permission, and
	// RouteAuth cannot express a role.
	reg.Handle("POST /api/v1/evm/rules/{id}/approve", Permitted(middleware.PermApproveRule), http.HandlerFunc(m.h.ApproveRule))
	reg.Handle("POST /api/v1/evm/rules/{id}/reject", Permitted(middleware.PermApproveRule), http.HandlerFunc(m.h.RejectRule))
	reg.Handle("POST /api/v1/evm/rules/{id}/propose", Permitted(middleware.PermProposeRule), http.HandlerFunc(m.h.ProposeRule))

	// ---------- the two validate endpoints ----------
	//
	// ⛔ PermListRules on both, and 2026-09-14 deliberately LEFT them there.
	// They are POSTs that create nothing — they run the rules' own test cases —
	// so this is route-mutating-perm's known false-positive direction, and the
	// check that actually narrows them is an admin *role* test inside the handler
	// (RuleHandler.requireAdmin, copied word for word from the ServeHTTP branch;
	// pinned by TestRuleRoutes_ValidateAdminCheckIsStillInTheHandler). RouteAuth
	// expresses permissions, not roles.
	//
	// ⚠️ There is no permission that would improve them: approve_rule is
	// admin-only and would duplicate the role check at the cost of pretending
	// validate is an approval; create_rule_self would say they write, which they
	// do not. ⭐ So their route-mutating-perm rows stay, with the reason upgraded
	// from "nobody has judged this" to "judged, and left". Proposal §2.1 names
	// this exact pair.
	//
	// ⚠️ "validate" is one legal path segment, so POST /api/v1/evm/rules/validate
	// is also matched by POST /api/v1/evm/rules/{id} (slice 3). The literal is a
	// strict subset of the wildcard, which is proposal §2.2's safe overlap: the
	// mux takes both and prefers the literal. ⭐ A GET on that path falls to the
	// item route and reads a rule whose id is "validate" — 404 — which is exactly
	// what ServeHTTP did with it.
	reg.Handle("POST /api/v1/evm/rules/validate", Permitted(middleware.PermListRules), http.HandlerFunc(m.h.ValidateRules))
	reg.Handle("POST /api/v1/evm/rules/{id}/validate", Permitted(middleware.PermListRules), http.HandlerFunc(m.h.ValidateRule))

	// ---------- slice 2: the two budget sub-resources ----------
	//
	// ⚠️ Conditional, exactly as the ServeHTTP branches were: both required
	// `h.budgetRepo != nil` before dispatching, and a daemon without one answered
	// 400 for either path. ⛔ Registering them anyway would change that answer to
	// a 500 nobody has seen.
	//
	// ⭐ POST .../budgets/reset is the one route in this file that already
	// existed as a named pattern: setupRoutes registered it separately, with
	// PermManageBudgets rather than the prefix's PermListRules, and then sent it
	// to the same ServeHTTP. It keeps that permission byte for byte — the line in
	// route-perm-bindings.txt does not move, only the file it is declared in.
	if m.withBudgets {
		reg.Handle("GET /api/v1/evm/rules/{id}/budgets", Permitted(middleware.PermListRules), http.HandlerFunc(m.h.ListBudgets))
		reg.Handle("POST /api/v1/evm/rules/{id}/budgets/reset", Permitted(middleware.PermManageBudgets), http.HandlerFunc(m.h.ResetBudgets))
	}
}
