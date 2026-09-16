package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/settings"
)

// SettingsHandler exposes the runtime-mutable configuration groups stored in
// system_settings. It is the HTTP surface that backs `remote-signer settings
// get/set` and the only way an operator should be editing security/notify/etc.
// without restarting the daemon (config.yaml stays the bootstrap minimum).
//
// All endpoints require admin role. Writes are recorded via the audit logger.
//
// # ⭐ Why there are eighteen methods here and not two (proposal S5)
//
// This used to be one ServeHTTP behind one method-less pattern,
// "/api/v1/admin/settings/", which cut the group out of r.URL.Path and switched
// on it twice — once to pick a snapshot to return, once to pick a struct to
// decode the request body into. ⛔ That last part is the thing OpenAPI cannot
// describe at all: one path, nine different request-body schemas, chosen by a
// value inside the path. A spec has one requestBody per path+method, so the
// only honest thing it could say about this surface was nothing.
//
// One route per group per method makes each body a concrete type at a concrete
// path, which is the entire point of this step rather than a side effect of it.
// ⛔ Do not collapse these back into a `{group}` wildcard route: that would put
// the group back inside the path *value* and restore exactly the shape that
// cannot be expressed — the route table would look decomposed while the schema
// problem stayed.
//
// ⚠️ The nine group identifiers contain dots ("evm.foundry") but never slashes,
// so each is a single literal path segment and Go's mux matches it as one.
type SettingsHandler struct {
	mgr   *settings.Manager
	log   *slog.Logger
	audit *audit.AuditLogger // optional

	onSecurityUpdated func()
}

// NewSettingsHandler returns a handler bound to the given settings manager.
func NewSettingsHandler(mgr *settings.Manager, log *slog.Logger) *SettingsHandler {
	return &SettingsHandler{mgr: mgr, log: log}
}

// SetOnSecurityUpdated registers a hook invoked after security settings are saved.
func (h *SettingsHandler) SetOnSecurityUpdated(fn func()) {
	h.onSecurityUpdated = fn
}

// SetAuditLogger wires an audit logger; writes record [admin, group, summary]
// so the change history lives alongside other admin operations.
func (h *SettingsHandler) SetAuditLogger(a *audit.AuditLogger) { h.audit = a }

// ---------------------------------------------------------------------------
// GET — one endpoint per group
// ---------------------------------------------------------------------------
//
// ⚠️ There is no "unknown group" arm any more. snapshot() used to answer 404
// "unknown settings group: x" for a group nobody had implemented; a group with
// no route is now simply not routed, and a daemon answers the /api/v1/ JSON 404
// instead. That is a *narrower* handler, not a lost check — the set of groups
// this API serves is now stated where the mux enforces it.

// GetSecurity returns the current security snapshot.
//
//	@Summary	Read the security settings
//	@Description	Returns the group as the daemon is currently running it — the live snapshot, not what config.yaml said at boot.
//	@Tags	settings
//	@Produce	json
//	@Success	200	{object}	settings.SecuritySnapshot
//	@Failure	401	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/security [get]
func (h *SettingsHandler) GetSecurity(w http.ResponseWriter, _ *http.Request) {
	writeSettingsJSON(w, http.StatusOK, h.mgr.Security())
}

// GetNotify returns the current notification snapshot.
//
//	@Summary	Read the notification settings
//	@Description	Returns the group as the daemon is currently running it — the live snapshot, not what config.yaml said at boot.
//	@Tags	settings
//	@Produce	json
//	@Success	200	{object}	settings.NotifySnapshot
//	@Failure	401	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/notify [get]
func (h *SettingsHandler) GetNotify(w http.ResponseWriter, _ *http.Request) {
	writeSettingsJSON(w, http.StatusOK, h.mgr.Notify())
}

// GetAuditMonitor returns the current audit-monitor snapshot.
//
//	@Summary	Read the audit-monitor settings
//	@Description	Returns the group as the daemon is currently running it — the live snapshot, not what config.yaml said at boot.
//	@Tags	settings
//	@Produce	json
//	@Success	200	{object}	settings.AuditMonitorSnapshot
//	@Failure	401	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/audit_monitor [get]
func (h *SettingsHandler) GetAuditMonitor(w http.ResponseWriter, _ *http.Request) {
	writeSettingsJSON(w, http.StatusOK, h.mgr.AuditMonitor())
}

// GetBlocklist returns the current dynamic-blocklist snapshot.
//
//	@Summary	Read the dynamic-blocklist settings
//	@Description	Returns the group as the daemon is currently running it — the live snapshot, not what config.yaml said at boot.
//	@Tags	settings
//	@Produce	json
//	@Success	200	{object}	settings.BlocklistSnapshot
//	@Failure	401	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/evm.dynamic_blocklist [get]
func (h *SettingsHandler) GetBlocklist(w http.ResponseWriter, _ *http.Request) {
	writeSettingsJSON(w, http.StatusOK, h.mgr.Blocklist())
}

// GetSimulation returns the current simulation snapshot.
//
//	@Summary	Read the simulation settings
//	@Description	Returns the group as the daemon is currently running it — the live snapshot, not what config.yaml said at boot.
//	@Tags	settings
//	@Produce	json
//	@Success	200	{object}	settings.SimulationSnapshot
//	@Failure	401	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/evm.simulation [get]
func (h *SettingsHandler) GetSimulation(w http.ResponseWriter, _ *http.Request) {
	writeSettingsJSON(w, http.StatusOK, h.mgr.Simulation())
}

// GetFoundry returns the current Foundry snapshot.
//
//	@Summary	Read the Foundry settings
//	@Description	Returns the group as the daemon is currently running it — the live snapshot, not what config.yaml said at boot.
//	@Tags	settings
//	@Produce	json
//	@Success	200	{object}	settings.FoundrySnapshot
//	@Failure	401	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/evm.foundry [get]
func (h *SettingsHandler) GetFoundry(w http.ResponseWriter, _ *http.Request) {
	writeSettingsJSON(w, http.StatusOK, h.mgr.Foundry())
}

// GetRPCGateway returns the current RPC-gateway snapshot.
//
//	@Summary	Read the RPC-gateway settings
//	@Description	Returns the group as the daemon is currently running it — the live snapshot, not what config.yaml said at boot.
//	@Tags	settings
//	@Produce	json
//	@Success	200	{object}	settings.RPCGatewaySnapshot
//	@Failure	401	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/evm.rpc_gateway [get]
func (h *SettingsHandler) GetRPCGateway(w http.ResponseWriter, _ *http.Request) {
	writeSettingsJSON(w, http.StatusOK, h.mgr.RPCGateway())
}

// GetMaterialCheck returns the current material-check snapshot.
//
//	@Summary	Read the material-check settings
//	@Description	Returns the group as the daemon is currently running it — the live snapshot, not what config.yaml said at boot.
//	@Tags	settings
//	@Produce	json
//	@Success	200	{object}	settings.MaterialCheckSnapshot
//	@Failure	401	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/evm.material_check [get]
func (h *SettingsHandler) GetMaterialCheck(w http.ResponseWriter, _ *http.Request) {
	writeSettingsJSON(w, http.StatusOK, h.mgr.MaterialCheck())
}

// GetWeb returns the current Web UI snapshot.
//
//	@Summary	Read the Web UI settings
//	@Description	Returns the group as the daemon is currently running it — the live snapshot, not what config.yaml said at boot.
//	@Tags	settings
//	@Produce	json
//	@Success	200	{object}	settings.WebSnapshot
//	@Failure	401	{object}	map[string]string
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/web [get]
func (h *SettingsHandler) GetWeb(w http.ResponseWriter, _ *http.Request) {
	writeSettingsJSON(w, http.StatusOK, h.mgr.Web())
}

// ---------------------------------------------------------------------------
// PUT — one endpoint per group, each with its own body type
// ---------------------------------------------------------------------------

// PutSecurity merges a patch into the security snapshot.
//
// ⚠️ The only group with an after-save hook: the router passes syncApprovalGuard
// through SetOnSecurityUpdated, so a changed approval policy takes effect
// without a restart. Written here rather than inside putSettingsGroup because
// "security is special" is a fact about this endpoint, not about the mechanism.
//
// ⛔ It is also the only group that MERGES. The other eight still replace
// wholesale, and their docs still say so — ⚠️ do not "unify" those sentences:
// eight of them are true.
//
//	@Summary	Update the security settings (partial patch)
//	@Description	⭐ MERGE semantics, since 2026-09-16: a field **absent from the body keeps its current value**, and only fields actually present are written. To flip one switch, send that one field.
//	@Description	⛔ This differs from the other eight settings groups, which still REPLACE wholesale — see each of their descriptions. Security was changed first because half its fields are security switches and every omission failed in the same direction, **looser**: nonce_required / manual_approval_enabled / require_approval_for_agent_rules all default to true and became false; max_keystores_per_key / max_hd_wallets_per_key default to 5 / 3 and became 0 — and 0 on those two means **no limit**.
//	@Description	⚠️ Values you do write still apply, including `false` and `0`. Absence (JSON null / omitted key) is the only thing that means "leave it alone" — so a switch stays switchable off.
//	@Description	⚠️ The 200 body is the manager's snapshot re-read after the write, so it can differ from what was sent if the store normalised anything.
//	@Description	⚠️ Error bodies here are a bare text/plain line, NOT the `{"error":...}` JSON every other endpoint answers with — the handler uses http.Error. ⛔ The 400 and 500 below still say `application/json` because swag's @Produce is per-operation and cannot vary by response; the schema is `string` and this sentence is the correction. Documented rather than fixed: making the handler answer JSON is a response-shape change.
//	@Tags	settings
//	@Accept	json
//	@Produce	json
//	@Param	body	body	settings.SecuritySnapshot	true	"partial patch — omitted fields keep their current value"
//	@Success	200	{object}	settings.SecuritySnapshot
//	@Failure	400	{string}	string	"invalid JSON (text/plain)"
//	@Failure	401	{object}	map[string]string
//	@Failure	500	{string}	string	"the store rejected the write (text/plain)"
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/security [put]
func (h *SettingsHandler) PutSecurity(w http.ResponseWriter, r *http.Request) {
	putSettingsGroup(h, w, r, settings.GroupSecurity, h.mgr.UpdateSecurity,
		func() any { return h.mgr.Security() }, h.onSecurityUpdated)
}

// PutNotify replaces the notification snapshot.
//
//	@Summary	Replace the notification settings
//	@Description	⛔ This REPLACES the whole group, it does not merge. The handler decodes the body into a zero-valued snapshot and persists that struct as it stands, so **every field absent from the body is written as its zero value** — omitting a field turns it off rather than leaving it alone. Read the group first and send it back with your edit applied.
//	@Description	⚠️ The 200 body is the manager's snapshot re-read after the write, so it can differ from what was sent if the store normalised anything.
//	@Description	⚠️ Error bodies here are a bare text/plain line, NOT the `{"error":...}` JSON every other endpoint answers with — the handler uses http.Error. ⛔ The 400 and 500 below still say `application/json` because swag's @Produce is per-operation and cannot vary by response; the schema is `string` and this sentence is the correction. Documented rather than fixed: making the handler answer JSON is a response-shape change.
//	@Tags	settings
//	@Accept	json
//	@Produce	json
//	@Param	body	body	settings.NotifySnapshot	true	"the complete replacement snapshot"
//	@Success	200	{object}	settings.NotifySnapshot
//	@Failure	400	{string}	string	"invalid JSON (text/plain)"
//	@Failure	401	{object}	map[string]string
//	@Failure	500	{string}	string	"the store rejected the write (text/plain)"
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/notify [put]
func (h *SettingsHandler) PutNotify(w http.ResponseWriter, r *http.Request) {
	putSettingsGroup(h, w, r, settings.GroupNotify, h.mgr.UpdateNotify,
		func() any { return h.mgr.Notify() }, nil)
}

// PutAuditMonitor replaces the audit-monitor snapshot.
//
//	@Summary	Replace the audit-monitor settings
//	@Description	⛔ This REPLACES the whole group, it does not merge. The handler decodes the body into a zero-valued snapshot and persists that struct as it stands, so **every field absent from the body is written as its zero value** — omitting a field turns it off rather than leaving it alone. Read the group first and send it back with your edit applied.
//	@Description	⚠️ The 200 body is the manager's snapshot re-read after the write, so it can differ from what was sent if the store normalised anything.
//	@Description	⚠️ Error bodies here are a bare text/plain line, NOT the `{"error":...}` JSON every other endpoint answers with — the handler uses http.Error. ⛔ The 400 and 500 below still say `application/json` because swag's @Produce is per-operation and cannot vary by response; the schema is `string` and this sentence is the correction. Documented rather than fixed: making the handler answer JSON is a response-shape change.
//	@Tags	settings
//	@Accept	json
//	@Produce	json
//	@Param	body	body	settings.AuditMonitorSnapshot	true	"the complete replacement snapshot"
//	@Success	200	{object}	settings.AuditMonitorSnapshot
//	@Failure	400	{string}	string	"invalid JSON (text/plain)"
//	@Failure	401	{object}	map[string]string
//	@Failure	500	{string}	string	"the store rejected the write (text/plain)"
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/audit_monitor [put]
func (h *SettingsHandler) PutAuditMonitor(w http.ResponseWriter, r *http.Request) {
	putSettingsGroup(h, w, r, settings.GroupAuditMonitor, h.mgr.UpdateAuditMonitor,
		func() any { return h.mgr.AuditMonitor() }, nil)
}

// PutBlocklist replaces the dynamic-blocklist snapshot.
//
//	@Summary	Replace the dynamic-blocklist settings
//	@Description	⛔ This REPLACES the whole group, it does not merge. The handler decodes the body into a zero-valued snapshot and persists that struct as it stands, so **every field absent from the body is written as its zero value** — omitting a field turns it off rather than leaving it alone. Read the group first and send it back with your edit applied.
//	@Description	⚠️ The 200 body is the manager's snapshot re-read after the write, so it can differ from what was sent if the store normalised anything.
//	@Description	⚠️ Error bodies here are a bare text/plain line, NOT the `{"error":...}` JSON every other endpoint answers with — the handler uses http.Error. ⛔ The 400 and 500 below still say `application/json` because swag's @Produce is per-operation and cannot vary by response; the schema is `string` and this sentence is the correction. Documented rather than fixed: making the handler answer JSON is a response-shape change.
//	@Tags	settings
//	@Accept	json
//	@Produce	json
//	@Param	body	body	settings.BlocklistSnapshot	true	"the complete replacement snapshot"
//	@Success	200	{object}	settings.BlocklistSnapshot
//	@Failure	400	{string}	string	"invalid JSON (text/plain)"
//	@Failure	401	{object}	map[string]string
//	@Failure	500	{string}	string	"the store rejected the write (text/plain)"
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/evm.dynamic_blocklist [put]
func (h *SettingsHandler) PutBlocklist(w http.ResponseWriter, r *http.Request) {
	putSettingsGroup(h, w, r, settings.GroupBlocklist, h.mgr.UpdateBlocklist,
		func() any { return h.mgr.Blocklist() }, nil)
}

// PutSimulation replaces the simulation snapshot.
//
//	@Summary	Replace the simulation settings
//	@Description	⛔ This REPLACES the whole group, it does not merge. The handler decodes the body into a zero-valued snapshot and persists that struct as it stands, so **every field absent from the body is written as its zero value** — omitting a field turns it off rather than leaving it alone. Read the group first and send it back with your edit applied.
//	@Description	⚠️ The 200 body is the manager's snapshot re-read after the write, so it can differ from what was sent if the store normalised anything.
//	@Description	⚠️ Error bodies here are a bare text/plain line, NOT the `{"error":...}` JSON every other endpoint answers with — the handler uses http.Error. ⛔ The 400 and 500 below still say `application/json` because swag's @Produce is per-operation and cannot vary by response; the schema is `string` and this sentence is the correction. Documented rather than fixed: making the handler answer JSON is a response-shape change.
//	@Tags	settings
//	@Accept	json
//	@Produce	json
//	@Param	body	body	settings.SimulationSnapshot	true	"the complete replacement snapshot"
//	@Success	200	{object}	settings.SimulationSnapshot
//	@Failure	400	{string}	string	"invalid JSON (text/plain)"
//	@Failure	401	{object}	map[string]string
//	@Failure	500	{string}	string	"the store rejected the write (text/plain)"
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/evm.simulation [put]
func (h *SettingsHandler) PutSimulation(w http.ResponseWriter, r *http.Request) {
	putSettingsGroup(h, w, r, settings.GroupSimulation, h.mgr.UpdateSimulation,
		func() any { return h.mgr.Simulation() }, nil)
}

// PutFoundry replaces the Foundry snapshot.
//
//	@Summary	Replace the Foundry settings
//	@Description	⛔ This REPLACES the whole group, it does not merge. The handler decodes the body into a zero-valued snapshot and persists that struct as it stands, so **every field absent from the body is written as its zero value** — omitting a field turns it off rather than leaving it alone. Read the group first and send it back with your edit applied.
//	@Description	⚠️ The 200 body is the manager's snapshot re-read after the write, so it can differ from what was sent if the store normalised anything.
//	@Description	⚠️ Error bodies here are a bare text/plain line, NOT the `{"error":...}` JSON every other endpoint answers with — the handler uses http.Error. ⛔ The 400 and 500 below still say `application/json` because swag's @Produce is per-operation and cannot vary by response; the schema is `string` and this sentence is the correction. Documented rather than fixed: making the handler answer JSON is a response-shape change.
//	@Tags	settings
//	@Accept	json
//	@Produce	json
//	@Param	body	body	settings.FoundrySnapshot	true	"the complete replacement snapshot"
//	@Success	200	{object}	settings.FoundrySnapshot
//	@Failure	400	{string}	string	"invalid JSON (text/plain)"
//	@Failure	401	{object}	map[string]string
//	@Failure	500	{string}	string	"the store rejected the write (text/plain)"
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/evm.foundry [put]
func (h *SettingsHandler) PutFoundry(w http.ResponseWriter, r *http.Request) {
	putSettingsGroup(h, w, r, settings.GroupFoundry, h.mgr.UpdateFoundry,
		func() any { return h.mgr.Foundry() }, nil)
}

// PutRPCGateway replaces the RPC-gateway snapshot.
//
//	@Summary	Replace the RPC-gateway settings
//	@Description	⛔ This REPLACES the whole group, it does not merge. The handler decodes the body into a zero-valued snapshot and persists that struct as it stands, so **every field absent from the body is written as its zero value** — omitting a field turns it off rather than leaving it alone. Read the group first and send it back with your edit applied.
//	@Description	⚠️ The 200 body is the manager's snapshot re-read after the write, so it can differ from what was sent if the store normalised anything.
//	@Description	⚠️ Error bodies here are a bare text/plain line, NOT the `{"error":...}` JSON every other endpoint answers with — the handler uses http.Error. ⛔ The 400 and 500 below still say `application/json` because swag's @Produce is per-operation and cannot vary by response; the schema is `string` and this sentence is the correction. Documented rather than fixed: making the handler answer JSON is a response-shape change.
//	@Tags	settings
//	@Accept	json
//	@Produce	json
//	@Param	body	body	settings.RPCGatewaySnapshot	true	"the complete replacement snapshot"
//	@Success	200	{object}	settings.RPCGatewaySnapshot
//	@Failure	400	{string}	string	"invalid JSON (text/plain)"
//	@Failure	401	{object}	map[string]string
//	@Failure	500	{string}	string	"the store rejected the write (text/plain)"
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/evm.rpc_gateway [put]
func (h *SettingsHandler) PutRPCGateway(w http.ResponseWriter, r *http.Request) {
	putSettingsGroup(h, w, r, settings.GroupRPCGateway, h.mgr.UpdateRPCGateway,
		func() any { return h.mgr.RPCGateway() }, nil)
}

// PutMaterialCheck replaces the material-check snapshot.
//
//	@Summary	Replace the material-check settings
//	@Description	⛔ This REPLACES the whole group, it does not merge. The handler decodes the body into a zero-valued snapshot and persists that struct as it stands, so **every field absent from the body is written as its zero value** — omitting a field turns it off rather than leaving it alone. Read the group first and send it back with your edit applied.
//	@Description	⚠️ The 200 body is the manager's snapshot re-read after the write, so it can differ from what was sent if the store normalised anything.
//	@Description	⚠️ Error bodies here are a bare text/plain line, NOT the `{"error":...}` JSON every other endpoint answers with — the handler uses http.Error. ⛔ The 400 and 500 below still say `application/json` because swag's @Produce is per-operation and cannot vary by response; the schema is `string` and this sentence is the correction. Documented rather than fixed: making the handler answer JSON is a response-shape change.
//	@Tags	settings
//	@Accept	json
//	@Produce	json
//	@Param	body	body	settings.MaterialCheckSnapshot	true	"the complete replacement snapshot"
//	@Success	200	{object}	settings.MaterialCheckSnapshot
//	@Failure	400	{string}	string	"invalid JSON (text/plain)"
//	@Failure	401	{object}	map[string]string
//	@Failure	500	{string}	string	"the store rejected the write (text/plain)"
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/evm.material_check [put]
func (h *SettingsHandler) PutMaterialCheck(w http.ResponseWriter, r *http.Request) {
	putSettingsGroup(h, w, r, settings.GroupMaterialCheck, h.mgr.UpdateMaterialCheck,
		func() any { return h.mgr.MaterialCheck() }, nil)
}

// PutWeb replaces the Web UI snapshot.
//
//	@Summary	Replace the Web UI settings
//	@Description	⛔ This REPLACES the whole group, it does not merge. The handler decodes the body into a zero-valued snapshot and persists that struct as it stands, so **every field absent from the body is written as its zero value** — omitting a field turns it off rather than leaving it alone. Read the group first and send it back with your edit applied.
//	@Description	⚠️ The 200 body is the manager's snapshot re-read after the write, so it can differ from what was sent if the store normalised anything.
//	@Description	⚠️ Error bodies here are a bare text/plain line, NOT the `{"error":...}` JSON every other endpoint answers with — the handler uses http.Error. ⛔ The 400 and 500 below still say `application/json` because swag's @Produce is per-operation and cannot vary by response; the schema is `string` and this sentence is the correction. Documented rather than fixed: making the handler answer JSON is a response-shape change.
//	@Tags	settings
//	@Accept	json
//	@Produce	json
//	@Param	body	body	settings.WebSnapshot	true	"the complete replacement snapshot"
//	@Success	200	{object}	settings.WebSnapshot
//	@Failure	400	{string}	string	"invalid JSON (text/plain)"
//	@Failure	401	{object}	map[string]string
//	@Failure	500	{string}	string	"the store rejected the write (text/plain)"
//	@Security	Ed25519Signature
//	@Router	/api/v1/admin/settings/web [put]
func (h *SettingsHandler) PutWeb(w http.ResponseWriter, r *http.Request) {
	putSettingsGroup(h, w, r, settings.GroupWeb, h.mgr.UpdateWeb,
		func() any { return h.mgr.Web() }, nil)
}

// putSettingsGroup is the one PUT body every group shares, with the *type* it
// decodes as the parameter. It is byte-for-byte the sequence the nine arms of
// the old handlePut switch ran: decode, update, hook, audit, echo the manager's
// new view — including the status codes (400 on a decode failure, 500 on an
// update failure, 200 with the fresh snapshot on success).
//
// ⚠️ A free function rather than a method because Go methods cannot take type
// parameters. ⛔ It must stay a *shape* and not grow group-specific behaviour:
// the moment it needs to know which group it is serving, the nine endpoints
// have stopped being nine endpoints again.
func putSettingsGroup[T any](
	h *SettingsHandler,
	w http.ResponseWriter,
	r *http.Request,
	group settings.Group,
	update func(context.Context, *T, string) error,
	current func() any,
	after func(),
) {
	actor := settings.UpdatedByAPI
	if k := middleware.GetAPIKey(r.Context()); k != nil && k.ID != "" {
		actor = k.ID
	}

	var patch T
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := update(r.Context(), &patch, actor); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if after != nil {
		after()
	}
	h.recordAudit(r.Context(), actor, group, &patch)
	writeSettingsJSON(w, http.StatusOK, current())
}

func (h *SettingsHandler) recordAudit(ctx context.Context, actor string, group settings.Group, patch any) {
	if h.audit == nil {
		return
	}
	payload, _ := json.Marshal(patch)
	h.audit.LogSettingsUpdated(ctx, actor, string(group), string(payload))
}

func writeSettingsJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("settings: encode response", "err", err)
	}
}
