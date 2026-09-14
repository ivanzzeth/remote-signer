package evm

import (
	"fmt"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ruleIDPattern validates rule ID format. Accepts:
// - rule_<uuid>: API-created rules
// - cfg_<16hex> or cfg_<digits>: config rules (auto-generated or legacy)
// - <custom>: config custom IDs (alphanumeric, hyphen, underscore, 1-64 chars).
var ruleIDPattern = regexp.MustCompile(`^(rule_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|cfg_[0-9a-f]{16}|cfg_\d+|[a-zA-Z0-9][0-9A-Za-z_\-]{0,63})$`)

// blockedAgentRuleTypes are rule types that agents cannot create or modify to:
// engines that run operator-supplied code, and types that decide which signers
// may be used at all.
//
// ⚠️ Derived, not listed. As a literal this was fail-open — a new engine was
// permitted for agents by nobody having thought about it, and the engine that
// most needs blocking is exactly the kind someone adds last. Describing a new
// engine correctly in types.ruleTypes now blocks it here by construction.
//
// ⛔ Widening agent permissions by clearing a descriptor flag is the same
// mistake with an extra step. If a code-executing engine should be agent-
// writable, that belongs in an explicit exception here, with the reason.
var blockedAgentRuleTypes = func() map[types.RuleType]bool {
	m := map[types.RuleType]bool{}
	for _, d := range types.RuleTypes() {
		if d.ExecutesArbitraryCode || d.GovernsSignerAccess {
			m[d.Type] = true
		}
	}
	return m
}()

// blockedDevRuleTypes are rule types the dev role cannot create: dev may write
// policy, but not change who holds signing authority.
var blockedDevRuleTypes = func() map[types.RuleType]bool {
	m := map[types.RuleType]bool{}
	for _, d := range types.RuleTypes() {
		if d.GovernsSignerAccess {
			m[d.Type] = true
		}
	}
	return m
}()

// RuleHandler handles rule management endpoints
type RuleHandler struct {
	ruleRepo          storage.RuleRepository
	budgetRepo        storage.BudgetRepository
	templateRepo      storage.TemplateRepository
	apiKeyRepo        storage.APIKeyRepository
	solidityValidator *evmchain.SolidityRuleValidator
	jsEvaluator       *evmchain.JSRuleEvaluator
	auditLogger       *audit.AuditLogger
	readOnly          func() bool // when true, block all rule mutations via API
	logger            *slog.Logger
	maxRulesPerKey    func() int              // per-key rule count limit (0 = no limit)
	requireApproval   func() bool             // require admin approval for agent whitelist rules
	onRuleActivated   func(callerName string) // optional callback when rule becomes active
}

// RuleHandlerOption is a functional option for RuleHandler
type RuleHandlerOption func(*RuleHandler)

// WithSolidityValidator sets the Solidity rule validator for the handler
func WithSolidityValidator(validator *evmchain.SolidityRuleValidator) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.solidityValidator = validator
	}
}

// WithJSEvaluator sets the JS rule evaluator for test-case validation on API-created evm_js rules.
func WithJSEvaluator(eval *evmchain.JSRuleEvaluator) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.jsEvaluator = eval
	}
}

// WithAuditLogger sets the audit logger for rule CRUD audit events.
func WithAuditLogger(al *audit.AuditLogger) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.auditLogger = al
	}
}

// WithBudgetRepo sets the budget repository for GET /api/v1/evm/rules/{id}/budgets
// and budget auto-migration during rule updates.
func WithBudgetRepo(repo storage.BudgetRepository) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.budgetRepo = repo
	}
}

// WithTemplateRepo sets the template repository for budget auto-migration
// when Variables affecting the budget unit are changed during rule updates.
func WithTemplateRepo(repo storage.TemplateRepository) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.templateRepo = repo
	}
}

// WithReadOnly disables all rule mutation endpoints (create/update/delete).
func WithReadOnly(src func() bool) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.readOnly = src
	}
}

// WithAPIKeyRepo sets the API key repository for validating applied_to key IDs.
func WithAPIKeyRepo(repo storage.APIKeyRepository) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.apiKeyRepo = repo
	}
}

// WithMaxRulesPerKey sets the per-key rule count limit.
func WithMaxRulesPerKey(max func() int) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.maxRulesPerKey = max
	}
}

// WithRequireApproval enables admin approval for agent whitelist rules.
func WithRequireApproval(require func() bool) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.requireApproval = require
	}
}

// WithRuleActivatedCallback sets a callback invoked (asynchronously) when a
// rule transitions to active. It re-evaluates pending approval requests
// against the updated rule set so a newly-active whitelist rule can
// auto-approve requests that were waiting.
func WithRuleActivatedCallback(cb func(callerName string)) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.onRuleActivated = cb
	}
}

// NewRuleHandler creates a new rule handler
func NewRuleHandler(ruleRepo storage.RuleRepository, logger *slog.Logger, opts ...RuleHandlerOption) (*RuleHandler, error) {
	if ruleRepo == nil {
		return nil, fmt.Errorf("rule repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	h := &RuleHandler{
		ruleRepo: ruleRepo,
		logger:   logger,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h, nil
}

// ---------- named endpoints (proposal S8) ----------
//
// ⚠️ Each of these is one route in internal/api/module_rules.go.
//
// # What used to be here
//
// A ServeHTTP that was a second route table. Two method-less patterns —
// "/api/v1/evm/rules" and "/api/v1/evm/rules/", the latter matching every verb
// at every depth — reached it, and it then re-derived the endpoint from
// `strings.TrimPrefix(r.URL.Path, "/api/v1/evm/rules")` through seven
// strings.HasSuffix branches and two method switches: twelve endpoints behind
// one registration, the largest entry in the handler-path-dispatch baseline
// after settings. ⛔ Nothing that reads registrations could see any of it, and
// an @Router annotation on that function could only have been a guess (proposal
// §1.2, §3.3).
//
// What a request reaches is decided by the registration now, and the id comes
// from the {id} wildcard rather than from arithmetic on r.URL.Path.
//
// # ⛔ The guards that came with them, and where each one went
//
// These are copied from the ServeHTTP branch they replace, not re-derived — the
// step's whole risk is dropping one (proposal §2.5 puts rule.go last because
// "守卫最细,逐条搬运最容易掉字段"):
//
//	guard                                   was                          is
//	no API key → 401                        once, at the top, for all 12 requireAPIKey on each endpoint
//	validate is admin-only → 403            inside two branches          requireAdmin on those two
//	isRulePathID(id) → 400                  the bottom switch            GetRule/UpdateRule/DeleteRule
//	synthetic sim: id is not PATCHable →403 the PATCH arm                UpdateRule
//	len(id) <= 128 → the budget branches    two branches                 ListBudgets/ResetBudgets
//	id must not contain '/'                 five branches                {id} is one segment
//	method must be POST                     seven branches               the pattern carries the method
//	budgetRepo != nil                       two branches                 conditional registration
//
// ⛔ The admin check on validate is a permission decision and stays exactly
// where it was. Converting it into a route permission would change who may call
// those endpoints, which is the one thing a decomposition must not do.
//
// ⛔ The guards these carry are copied from the ServeHTTP branch they replace,
// not re-derived. Two of them are easy to lose and both were measured before
// the move: the unauthenticated 401 that ServeHTTP applied once, at the top,
// for all twelve endpoints (five of the twelve handlers do not check it
// themselves), and the admin check the validate branches make inside the
// handler. ⛔ That admin check is a permission decision and stays exactly where
// it is — turning it into a route permission would change who may call it,
// which is the one thing a decomposition must not do (proposal §2.5).

// requireAPIKey is the guard ServeHTTP applies before dispatching anywhere:
// no API key in the context, no endpoint. ⚠️ In production AuthMiddleware has
// already refused such a request, so this is defence in depth rather than the
// live check — but it is what these endpoints answered before, and five of them
// have no check of their own.
func (h *RuleHandler) requireAPIKey(w http.ResponseWriter, r *http.Request) bool {
	if middleware.GetAPIKey(r.Context()) == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return false
	}
	return true
}

// ListRules serves GET /api/v1/evm/rules.
//
//	@Summary	List rules
//	@Description	⛔ Scoped and REDACTED per caller: admin and dev see every rule, an agent or strategy key sees only rules that apply to it, and an AGENT key gets `config` stripped to null so rule script source never reaches it. `total` is recomputed after that filtering.
//	@Description	⚠️ `enabled`, `limit` and `offset` are parsed leniently — a malformed value leaves the default; the other filters answer 400.
//	@Tags	rules
//	@Produce	json
//	@Param	chain_type	query	string	false	"400 if unknown"
//	@Param	chain_id	query	string	false	"chain id"
//	@Param	signer_address	query	string	false	"0x + 40 hex"
//	@Param	owner	query	string	false	"owning api key id"
//	@Param	type	query	string	false	"400 if unknown"
//	@Param	source	query	string	false	"400 if unknown"
//	@Param	enabled	query	string	false	"enabled-only filter"
//	@Param	limit	query	int	false	"maximum rows"
//	@Param	offset	query	int	false	"rows to skip"
//	@Success	200	{object}	ListRulesResponse
//	@Failure	400	{object}	map[string]string
//	@Failure	401	{object}	map[string]string
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/rules [get]
func (h *RuleHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPIKey(w, r) {
		return
	}
	h.listRules(w, r)
}

// CreateRule serves POST /api/v1/evm/rules.
//
//	@Summary	Create a rule
//	@Description	⛔ TWO success codes, and the difference matters: 201 means the rule is ACTIVE and already deciding sign requests; 202 means it was stored as pending_approval and decides nothing until an admin approves it. Which one you get depends on your role and on security.require_approval_for_agent_rules — not on the request.
//	@Description	⚠️ Role restrictions are per rule TYPE: an agent key cannot create certain types and a dev key cannot create signer_restriction, both 403.
//	@Description	⚠️ A rule created active immediately re-evaluates pending sign requests in the background, so creating one can approve something that was already waiting.
//	@Tags	rules
//	@Accept	json
//	@Produce	json
//	@Param	body	body	CreateRuleRequest	true	"rule to create"
//	@Success	201	{object}	RuleResponse	"created and ACTIVE"
//	@Success	202	{object}	RuleResponse	"stored as pending_approval; inert until an admin approves"
//	@Failure	400	{object}	map[string]string
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"read-only mode, a rule type your role may not create, or the per-key rule limit"
//	@Failure	500	{object}	map[string]string
//	@Failure	503	{object}	map[string]string	"the rule type needs a toolchain (e.g. forge) that is not available"
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/rules [post]
func (h *RuleHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPIKey(w, r) {
		return
	}
	h.createRule(w, r)
}

// ruleItemID is the {id} of an item route, refused with the 400 the bottom of
// ServeHTTP gave it when it is not a shape a rule id can have.
//
// ⛔ Carried over verbatim. Unlike the sub-action branches, which accepted any
// slash-free segment and let the repository answer 404, the item switch ran
// isRulePathID first — so `GET /api/v1/evm/rules/not$valid` was a 400 and not a
// 404, and several tests say so.
func (h *RuleHandler) ruleItemID(w http.ResponseWriter, r *http.Request) (string, bool) {
	ruleID := r.PathValue("id")
	if !isRulePathID(ruleID) {
		respond.Error(w, "invalid rule_id format", http.StatusBadRequest, h.logger)
		return "", false
	}
	return ruleID, true
}

// GetRule serves GET /api/v1/evm/rules/{id}.
//
//	@Summary	Get one rule
//	@Description	⚠️ An id that is not a well-formed rule id is 400, not 404.
//	@Tags	rules
//	@Produce	json
//	@Param	id	path	string	true	"rule id"
//	@Success	200	{object}	RuleResponse
//	@Failure	400	{object}	map[string]string	"malformed rule id"
//	@Failure	401	{object}	map[string]string
//	@Failure	404	{object}	map[string]string
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/rules/{id} [get]
func (h *RuleHandler) GetRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPIKey(w, r) {
		return
	}
	ruleID, ok := h.ruleItemID(w, r)
	if !ok {
		return
	}
	h.getRule(w, r, ruleID)
}

// DeleteRule serves DELETE /api/v1/evm/rules/{id}.
//
//	@Summary	Delete a rule
//	@Description	⚠️ Deletes the rule's budgets with it.
//	@Description	⛔ Refused with 403 for: read-only mode, a config-sourced rule, an immutable rule, someone else's rule, and a synthetic simulation rule unless you are admin and it was auto-generated.
//	@Tags	rules
//	@Produce	json
//	@Param	id	path	string	true	"rule id"
//	@Success	204	"deleted; no body"
//	@Failure	400	{object}	map[string]string	"malformed rule id"
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string
//	@Failure	404	{object}	map[string]string
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/rules/{id} [delete]
func (h *RuleHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPIKey(w, r) {
		return
	}
	ruleID, ok := h.ruleItemID(w, r)
	if !ok {
		return
	}
	h.deleteRule(w, r, ruleID)
}

// UpdateRule serves PATCH /api/v1/evm/rules/{id}.
//
// ⚠️ The synthetic-id refusal is the PATCH arm's own, copied verbatim: a
// `sim:0x…` placeholder row exists only to satisfy the budget table's foreign
// key, and it is readable and deletable but not modifiable.
//
//	@Summary	Update a rule
//	@Description	Partial. ⛔ Like templates, `name` / `description` / `type` are plain strings, so an empty one means «leave unchanged» rather than «clear».
//	@Description	⛔ Four things are un-updatable and all answer 403: a config-sourced rule, an immutable rule, a synthetic `sim:` budget rule, and someone else's rule.
//	@Description	⚠️ Only admin may change `applied_to`.
//	@Tags	rules
//	@Accept	json
//	@Produce	json
//	@Param	id	path	string	true	"rule id"
//	@Param	body	body	UpdateRuleRequest	true	"fields to change"
//	@Success	200	{object}	RuleResponse
//	@Failure	400	{object}	map[string]string
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"read-only mode, config-sourced, immutable, synthetic, not yours, or a type/applied_to your role may not set"
//	@Failure	404	{object}	map[string]string
//	@Failure	500	{object}	map[string]string
//	@Failure	503	{object}	map[string]string	"a required toolchain is unavailable"
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/rules/{id} [patch]
func (h *RuleHandler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPIKey(w, r) {
		return
	}
	ruleID, ok := h.ruleItemID(w, r)
	if !ok {
		return
	}
	if isSyntheticBudgetRuleID(ruleID) {
		respond.Error(w, "cannot modify synthetic simulation budget rule", http.StatusForbidden, h.logger)
		return
	}
	h.updateRule(w, r, ruleID)
}

// ApproveRule serves POST /api/v1/evm/rules/{id}/approve.
//
//	@Summary	Approve a pending rule
//	@Description	Takes no request body. ⛔ Admin ROLE only, checked in the handler as 403 — the route's list_rules permission is not what gates this.
//	@Description	⚠️ A rule that is not in pending_approval is 400, and the message names its current status.
//	@Description	⚠️ Approving a PROPOSAL applies the proposed changes to the target rule. If the target has since been deleted the answer is 409 and the proposal is rejected; if the target became immutable it is 403.
//	@Tags	rules
//	@Produce	json
//	@Param	id	path	string	true	"rule id, or the id of a proposal"
//	@Success	200	{object}	RuleResponse
//	@Failure	400	{object}	map[string]string	"not pending approval, or the proposed change fails validation"
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"admin role required, or the target rule is immutable"
//	@Failure	404	{object}	map[string]string
//	@Failure	409	{object}	map[string]string	"the target rule of this proposal no longer exists"
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/rules/{id}/approve [post]
func (h *RuleHandler) ApproveRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPIKey(w, r) {
		return
	}
	h.approveRule(w, r, r.PathValue("id"))
}

// RejectRule serves POST /api/v1/evm/rules/{id}/reject.
//
//	@Summary	Reject a pending rule
//	@Description	⛔ Admin ROLE only, 403 otherwise.
//	@Description	⚠️ The body is optional AND unvalidated: a malformed one is swallowed and the rule is still rejected, with an empty reason. Sending no body at all works the same way.
//	@Description	⚠️ A rule that is not in pending_approval is 400.
//	@Tags	rules
//	@Accept	json
//	@Produce	json
//	@Param	id	path	string	true	"rule id"
//	@Param	body	body	RejectRuleRequest	false	"optional reason; a malformed body is ignored, not rejected"
//	@Success	200	{object}	RuleResponse
//	@Failure	400	{object}	map[string]string	"the rule is not pending approval"
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"admin role required"
//	@Failure	404	{object}	map[string]string
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/rules/{id}/reject [post]
func (h *RuleHandler) RejectRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPIKey(w, r) {
		return
	}
	h.rejectRule(w, r, r.PathValue("id"))
}

// ProposeRule serves POST /api/v1/evm/rules/{id}/propose.
//
//	@Summary	Propose changes to a rule
//	@Description	For keys that may not edit a rule directly: creates a SEPARATE pending rule row pointing at the target. Always 202 — nothing changes on the target until an admin approves the proposal.
//	@Description	⛔ Only agent and admin roles may propose; everyone else is 403.
//	@Description	⚠️ An empty body is a 400 («at least one field must be changed»), but no individual field is required — which is why none is marked so.
//	@Description	⚠️ A second pending proposal from the same key for the same rule is 409.
//	@Tags	rules
//	@Accept	json
//	@Produce	json
//	@Param	id	path	string	true	"id of the rule to change"
//	@Param	body	body	ProposeRuleRequest	true	"the changes being proposed; at least one field"
//	@Success	202	{object}	RuleResponse	"the proposal row; the target rule is unchanged"
//	@Failure	400	{object}	map[string]string	"no changes, unknown type, the target is itself a proposal, or the target is not active"
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"role may not propose, read-only mode, config-sourced or immutable target, or the per-key rule limit"
//	@Failure	404	{object}	map[string]string	"no such target rule"
//	@Failure	409	{object}	map[string]string	"you already have a pending proposal for this rule"
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/rules/{id}/propose [post]
func (h *RuleHandler) ProposeRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPIKey(w, r) {
		return
	}
	h.proposeRule(w, r, r.PathValue("id"))
}

// requireAdmin is the ServeHTTP validate branches' own check, copied verbatim.
//
// ⛔ It is a permission decision that lives in the handler and stays there. Both
// validate endpoints are registered with PermListRules, exactly as the prefix
// declared them, and this admin check is what actually narrows them — RouteAuth
// cannot express a role, and converting it into a route permission would change
// who may call these endpoints. That is the one thing a decomposition must not
// do (proposal §2.5, §2.1).
func (h *RuleHandler) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return false
	}
	if !apiKey.IsAdmin() {
		respond.Error(w, "forbidden: admin role required", http.StatusForbidden, h.logger)
		return false
	}
	return true
}

// ValidateRules serves POST /api/v1/evm/rules/validate — batch validation.
// ⛔ Admin only, checked here rather than on the route. See requireAdmin.
//
//	@Summary	Validate every evm_js rule
//	@Description	Runs the stored test cases of every enabled evm_js rule. Changes nothing and takes no request body.
//	@Description	⛔ Admin ROLE only, 403 otherwise.
//	@Description	⚠️ Always 200: failures are in `results[].valid` and in `passed`/`failed`, never in the status code.
//	@Description	⚠️ `full=true` loads every rule into one engine so cross-rule interference shows up. It silently falls back to isolated mode when no JS evaluator is wired — the response does not say which mode ran.
//	@Tags	rules
//	@Produce	json
//	@Param	full	query	bool	false	"only the literal `true` selects full-engine mode"
//	@Success	200	{object}	BatchValidateResponse
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"admin role required"
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/rules/validate [post]
func (h *RuleHandler) ValidateRules(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	h.validateRules(w, r)
}

// ValidateRule serves POST /api/v1/evm/rules/{id}/validate.
// ⛔ Admin only, checked here rather than on the route. See requireAdmin.
//
//	@Summary	Validate one rule's test cases
//	@Description	Changes nothing and takes no request body.
//	@Description	⛔ Admin ROLE only, 403 otherwise. ⛔ evm_js rules only — any other type is 400.
//	@Description	⚠️ A rule with no test cases is 200 with an empty result set, which reads as a pass.
//	@Tags	rules
//	@Produce	json
//	@Param	id	path	string	true	"rule id"
//	@Success	200	{object}	ValidateRuleResponse
//	@Failure	400	{object}	map[string]string	"not an evm_js rule, or its test_cases do not parse"
//	@Failure	401	{object}	map[string]string
//	@Failure	403	{object}	map[string]string	"admin role required"
//	@Failure	404	{object}	map[string]string
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/rules/{id}/validate [post]
func (h *RuleHandler) ValidateRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	h.validateRule(w, r, r.PathValue("id"))
}

// maxBudgetRuleIDLen is the length cap the two budget branches of ServeHTTP
// applied to the id before dispatching (`len(ruleID) <= 128`).
//
// ⛔ Carried over deliberately. It is the one guard in this surface that {id}
// does not reproduce: the wildcard bounds an id to a single path segment but not
// to a length, and without this a 200-character id would reach the repository
// and come back 200 with an empty budget list where it used to be refused. ⚠️ It
// is deliberately *looser* than isRulePathID (64 characters for the custom form)
// because config-expanded ids like erc20-schedule_erc20-transfer-limit are long
// and legitimate — the branch's own comment said so.
const maxBudgetRuleIDLen = 128

// ListBudgets serves GET /api/v1/evm/rules/{id}/budgets.
//
//	@Summary	List one rule's budgets
//	@Description	⚠️ Returns a bare JSON ARRAY, not an object with a `budgets` key — unlike the collection endpoint at /api/v1/evm/budgets.
//	@Description	⚠️ An unknown rule id is 200 with an empty array, not 404. Only an id longer than 128 characters is a 400.
//	@Tags	rules
//	@Produce	json
//	@Param	id	path	string	true	"rule id, at most 128 characters"
//	@Success	200	{array}	RuleBudgetListItem
//	@Failure	400	{object}	map[string]string	"rule id longer than 128 characters"
//	@Failure	401	{object}	map[string]string
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/rules/{id}/budgets [get]
func (h *RuleHandler) ListBudgets(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPIKey(w, r) {
		return
	}
	ruleID := r.PathValue("id")
	if len(ruleID) > maxBudgetRuleIDLen {
		respond.Error(w, "invalid rule_id format", http.StatusBadRequest, h.logger)
		return
	}
	// ⚠️ Unreachable in a daemon — rulesModule registers this route only when the
	// budget repository is wired, which is the same condition the ServeHTTP
	// branch checked. It is here because the alternative to an unreachable 500 is
	// a nil-interface panic inside listBudgets, and resetAllBudgets has answered
	// exactly this for as long as it has existed.
	if h.budgetRepo == nil {
		respond.Error(w, "budget repository not configured", http.StatusInternalServerError, h.logger)
		return
	}
	h.listBudgets(w, r, ruleID)
}

// ResetBudgets serves POST /api/v1/evm/rules/{id}/budgets/reset.
//
//	@Summary	Reset one rule's budgets
//	@Description	Zeroes spent and tx_count on every budget of this rule. Takes no request body.
//	@Description	⚠️ The 200 body has a single key `reset` — how many budget rows were zeroed, which is 0 when the rule had none.
//	@Tags	rules
//	@Produce	json
//	@Param	id	path	string	true	"rule id, at most 128 characters"
//	@Success	200	{object}	map[string]int	"single key `reset`"
//	@Failure	400	{object}	map[string]string	"rule id longer than 128 characters"
//	@Failure	401	{object}	map[string]string
//	@Failure	404	{object}	map[string]string
//	@Failure	500	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/evm/rules/{id}/budgets/reset [post]
func (h *RuleHandler) ResetBudgets(w http.ResponseWriter, r *http.Request) {
	if !h.requireAPIKey(w, r) {
		return
	}
	ruleID := r.PathValue("id")
	if len(ruleID) > maxBudgetRuleIDLen {
		respond.Error(w, "invalid rule_id format", http.StatusBadRequest, h.logger)
		return
	}
	h.resetAllBudgets(w, r, ruleID)
}

// isReadOnly reports whether write operations are blocked right now. See the
// note on Router.liveReadOnly: the setting behind it is runtime mutable, so a
// bool captured at construction freezes at boot.
func (h *RuleHandler) isReadOnly() bool {
	if h.readOnly == nil {
		return false
	}
	return h.readOnly()
}

// maxRulesPerKeyValue reads the limit at request time. See Router.liveInt: the setting
// behind it is runtime mutable, so a value captured at construction freezes at
// boot. nil means unset, which these fields already meant as 0.
func (h *RuleHandler) maxRulesPerKeyValue() int {
	if h.maxRulesPerKey == nil {
		return 0
	}
	return h.maxRulesPerKey()
}

// requireApprovalValue reads the setting at request time. See Router.liveDuration /
// liveBool: the snapshot behind it is reloaded from the database, so a value
// captured at construction freezes at boot. nil keeps the previous meaning of
// "unset" — the handler falls back to its own default.
func (h *RuleHandler) requireApprovalValue() bool {
	if h.requireApproval == nil {
		return false
	}
	return h.requireApproval()
}
