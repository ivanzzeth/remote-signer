package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// Permission represents a specific action that can be checked against an API key's role.
type Permission string

const (
	// Signing
	PermSignRequest Permission = "sign_request"

	// Request management
	PermListOwnRequests Permission = "list_own_requests"
	PermListAllRequests Permission = "list_all_requests"
	PermApproveRequest  Permission = "approve_request"

	// Rules
	PermListRules      Permission = "list_rules"
	PermCreateRuleSelf Permission = "create_rule_self"
	PermCreateRuleAny  Permission = "create_rule_any"
	PermModifyOwnRule  Permission = "modify_own_rule"
	PermModifyAnyRule  Permission = "modify_any_rule"
	PermDeleteOwnRule  Permission = "delete_own_rule"
	PermDeleteAnyRule  Permission = "delete_any_rule"
	PermApproveRule    Permission = "approve_rule"

	// Budgets
	PermReadBudgets Permission = "read_budgets"

	// Templates
	PermReadTemplates      Permission = "read_templates"
	PermInstantiateTemplate Permission = "instantiate_template"

	// Presets
	PermReadPresets  Permission = "read_presets"
	PermApplyPreset  Permission = "apply_preset"

	// Signers
	PermReadSigners   Permission = "read_signers"
	PermCreateSigners Permission = "create_signers"
	PermUnlockSigner  Permission = "unlock_signer"

	// HD Wallets
	PermReadHDWallets  Permission = "read_hd_wallets"
	PermCreateHDWallet Permission = "create_hd_wallet"

	// API Keys
	PermManageAPIKeys Permission = "manage_api_keys"

	// Audit
	PermReadAudit Permission = "read_audit"

	// System
	PermReadMetrics Permission = "read_metrics"

	// ACLs
	PermReadACLs Permission = "read_acls"

	// Guard
	PermResumeGuard Permission = "resume_guard"

	// Signer ownership
	PermApproveSigner Permission = "approve_signer"
)

// rolePermissions is the static permission matrix matching Section 2.2 of the design doc.
// It maps each role to the set of permissions it holds.
var rolePermissions = map[types.APIKeyRole]map[Permission]bool{
	types.RoleAdmin: {
		PermSignRequest:         true,
		PermListOwnRequests:     true,
		PermListAllRequests:     true,
		PermApproveRequest:      true,
		PermListRules:           true,
		PermCreateRuleSelf:      true,
		PermCreateRuleAny:       true,
		PermModifyOwnRule:       true,
		PermModifyAnyRule:       true,
		PermDeleteOwnRule:       true,
		PermDeleteAnyRule:       true,
		PermApproveRule:         true,
		PermReadBudgets:         true,
		PermReadTemplates:       true,
		PermInstantiateTemplate: true,
		PermReadPresets:         true,
		PermApplyPreset:         true,
		PermReadSigners:         true,
		PermCreateSigners:       true,
		PermUnlockSigner:        true,
		PermReadHDWallets:       true,
		PermCreateHDWallet:      true,
		PermManageAPIKeys:       true,
		PermReadAudit:           true,
		PermReadMetrics:         true,
		PermReadACLs:            true,
		PermResumeGuard:         true,
		PermApproveSigner:       true,
	},
	types.RoleDev: {
		PermSignRequest:         true,
		PermListOwnRequests:     true,
		PermListAllRequests:     true,
		PermListRules:           true,
		PermCreateRuleSelf:      true,
		PermModifyOwnRule:       true,
		PermDeleteOwnRule:       true,
		PermReadBudgets:         true,
		PermReadTemplates:       true,
		PermReadPresets:         true,
		PermReadSigners:         true,
		PermCreateSigners:       true,
		PermReadHDWallets:       true,
		PermReadAudit:           true,
		PermReadMetrics:         true,
	},
	types.RoleAgent: {
		PermSignRequest:     true,
		PermListOwnRequests: true,
		PermListRules:       true, // scoped to own + applied_to=self in handler
		PermCreateRuleSelf:  true, // declarative only, enforced in handler
		PermModifyOwnRule:   true, // declarative only
		PermDeleteOwnRule:   true,
		PermReadBudgets:     true, // own rules only, enforced in handler
		PermReadTemplates:   true,
		PermReadPresets:     true,
		PermReadSigners:     true, // own signers only
		PermCreateSigners:   true,
		PermReadHDWallets:   true, // own wallets only
	},
	types.RoleStrategy: {
		PermSignRequest:     true,
		PermListOwnRequests: true,
		PermReadSigners:     true, // own signers only, read-only
	},
}

// HasPermission checks if a role has a specific permission.
func HasPermission(role types.APIKeyRole, perm Permission) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	return perms[perm]
}

// RequirePermission creates a middleware that checks if the authenticated API key
// has the specified permission. Must be used after AuthMiddleware.
func RequirePermission(perm Permission, logger *slog.Logger, alertServices ...*SecurityAlertService) func(http.Handler) http.Handler {
	var alertService *SecurityAlertService
	if len(alertServices) > 0 {
		alertService = alertServices[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := GetAPIKey(r.Context())
			if apiKey == nil {
				logger.Error("rbac middleware: no API key in context",
					"path", r.URL.Path,
				)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if !HasPermission(apiKey.Role, perm) {
				logger.Warn("permission denied",
					"path", r.URL.Path,
					"method", r.Method,
					"api_key_id", apiKey.ID,
					"api_key_name", apiKey.Name,
					"role", apiKey.Role,
					"permission", perm,
				)
				if alertService != nil {
					clientIP, _ := r.Context().Value(ClientIPContextKey).(string)
					alertService.Alert(AlertAdminDenied, apiKey.ID,
						fmt.Sprintf("[Remote Signer] PERMISSION DENIED\n\nAPI Key: %s (%s)\nRole: %s\nPermission: %s\nIP: %s\nPath: %s %s\nTime: %s",
							apiKey.ID, apiKey.Name, apiKey.Role, perm, clientIP, r.Method, r.URL.Path,
							time.Now().UTC().Format(time.RFC3339)))
				}
				http.Error(w, "permission denied", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
