package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

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
type SettingsHandler struct {
	mgr   *settings.Manager
	log   *slog.Logger
	audit *audit.AuditLogger // optional
}

// NewSettingsHandler returns a handler bound to the given settings manager.
func NewSettingsHandler(mgr *settings.Manager, log *slog.Logger) *SettingsHandler {
	return &SettingsHandler{mgr: mgr, log: log}
}

// SetAuditLogger wires an audit logger; writes record [admin, group, summary]
// so the change history lives alongside other admin operations.
func (h *SettingsHandler) SetAuditLogger(a *audit.AuditLogger) { h.audit = a }

// ServeHTTP routes /api/v1/admin/settings/:group. GET returns the current
// snapshot as JSON; PUT replaces the entire snapshot for the named group.
func (h *SettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const prefix = "/api/v1/admin/settings/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	group := strings.TrimPrefix(r.URL.Path, prefix)
	if group == "" || strings.Contains(group, "/") {
		http.Error(w, "group required: /api/v1/admin/settings/<group>", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGet(w, r, settings.Group(group))
	case http.MethodPut:
		h.handlePut(w, r, settings.Group(group))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *SettingsHandler) handleGet(w http.ResponseWriter, _ *http.Request, group settings.Group) {
	snap, err := h.snapshot(group)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeSettingsJSON(w, http.StatusOK, snap)
}

func (h *SettingsHandler) handlePut(w http.ResponseWriter, r *http.Request, group settings.Group) {
	actor := settings.UpdatedByAPI
	if k := middleware.GetAPIKey(r.Context()); k != nil && k.ID != "" {
		actor = k.ID
	}
	switch group {
	case settings.GroupSecurity:
		var patch settings.SecuritySnapshot
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.mgr.UpdateSecurity(r.Context(), &patch, actor); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.recordAudit(r.Context(), actor, group, &patch)
		writeSettingsJSON(w, http.StatusOK, h.mgr.Security())
	case settings.GroupNotify:
		var patch settings.NotifySnapshot
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.mgr.UpdateNotify(r.Context(), &patch, actor); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.recordAudit(r.Context(), actor, group, &patch)
		writeSettingsJSON(w, http.StatusOK, h.mgr.Notify())
	case settings.GroupAuditMonitor:
		var patch settings.AuditMonitorSnapshot
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.mgr.UpdateAuditMonitor(r.Context(), &patch, actor); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.recordAudit(r.Context(), actor, group, &patch)
		writeSettingsJSON(w, http.StatusOK, h.mgr.AuditMonitor())
	case settings.GroupBlocklist:
		var patch settings.BlocklistSnapshot
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.mgr.UpdateBlocklist(r.Context(), &patch, actor); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.recordAudit(r.Context(), actor, group, &patch)
		writeSettingsJSON(w, http.StatusOK, h.mgr.Blocklist())
	case settings.GroupSimulation:
		var patch settings.SimulationSnapshot
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.mgr.UpdateSimulation(r.Context(), &patch, actor); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.recordAudit(r.Context(), actor, group, &patch)
		writeSettingsJSON(w, http.StatusOK, h.mgr.Simulation())
	case settings.GroupFoundry:
		var patch settings.FoundrySnapshot
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.mgr.UpdateFoundry(r.Context(), &patch, actor); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.recordAudit(r.Context(), actor, group, &patch)
		writeSettingsJSON(w, http.StatusOK, h.mgr.Foundry())
	case settings.GroupRPCGateway:
		var patch settings.RPCGatewaySnapshot
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.mgr.UpdateRPCGateway(r.Context(), &patch, actor); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.recordAudit(r.Context(), actor, group, &patch)
		writeSettingsJSON(w, http.StatusOK, h.mgr.RPCGateway())
	case settings.GroupMaterialCheck:
		var patch settings.MaterialCheckSnapshot
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.mgr.UpdateMaterialCheck(r.Context(), &patch, actor); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.recordAudit(r.Context(), actor, group, &patch)
		writeSettingsJSON(w, http.StatusOK, h.mgr.MaterialCheck())
	default:
		http.Error(w, "unknown or read-only settings group: "+string(group), http.StatusBadRequest)
	}
}

func (h *SettingsHandler) snapshot(group settings.Group) (any, error) {
	switch group {
	case settings.GroupSecurity:
		return h.mgr.Security(), nil
	case settings.GroupNotify:
		return h.mgr.Notify(), nil
	case settings.GroupFoundry:
		return h.mgr.Foundry(), nil
	case settings.GroupSimulation:
		return h.mgr.Simulation(), nil
	case settings.GroupBlocklist:
		return h.mgr.Blocklist(), nil
	case settings.GroupAuditMonitor:
		return h.mgr.AuditMonitor(), nil
	case settings.GroupRPCGateway:
		return h.mgr.RPCGateway(), nil
	case settings.GroupMaterialCheck:
		return h.mgr.MaterialCheck(), nil
	default:
		return nil, fmt.Errorf("unknown settings group: %s", group)
	}
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
