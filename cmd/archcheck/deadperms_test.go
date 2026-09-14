package main

import (
	"strings"
	"testing"
)

// deadPermKeys runs the check over literal sources and returns the finding keys.
func deadPermKeys(t *testing.T, srcByPkg map[string]string) []string {
	t.Helper()
	found, err := checkDeadPermissions(parseSources(t, srcByPkg))
	if err != nil {
		t.Fatalf("checkDeadPermissions: %v", err)
	}
	var keys []string
	for _, f := range found {
		keys = append(keys, f.Key)
	}
	return keys
}

// TestDeadPermissions_CatchesGrantedButNeverChecked is the regression this check
// exists for, in the shape of the real incident: PermInstantiateTemplate was
// declared, granted to two roles, and never read by any code — so creating,
// updating and deleting templates only ever required read_templates.
func TestDeadPermissions_CatchesGrantedButNeverChecked(t *testing.T) {
	keys := deadPermKeys(t, map[string]string{
		"internal/api/middleware": `package middleware
type Permission string
const (
	PermReadTemplates       Permission = "read_templates"
	PermInstantiateTemplate Permission = "instantiate_template"
)
var rolePermissions = map[string]map[Permission]bool{
	"admin": {PermReadTemplates: true, PermInstantiateTemplate: true},
}`,
		"internal/api": `package api
import "example.com/m/internal/api/middleware"
func register() {
	handle("GET /api/v1/templates", Permitted(middleware.PermReadTemplates))
}`,
	})
	if len(keys) != 1 {
		t.Fatalf("want exactly one dead permission, got %d: %v", len(keys), keys)
	}
	if keys[0] != "PermInstantiateTemplate" {
		t.Errorf("wrong permission reported: %s", keys[0])
	}
}

// TestDeadPermissions_EnforcedIsClean: a permission that any code reads is not
// dead. ⚠️ This is the false-positive direction, and it is the dangerous one —
// reporting a live permission sends someone to "fix" it by attaching it to a
// route, which is an authorization change.
func TestDeadPermissions_EnforcedIsClean(t *testing.T) {
	keys := deadPermKeys(t, map[string]string{
		"internal/api/middleware": `package middleware
type Permission string
const PermUnlockSigner Permission = "unlock_signer"
var rolePermissions = map[string]map[Permission]bool{
	"admin": {PermUnlockSigner: true},
}`,
		"internal/api": `package api
import "example.com/m/internal/api/middleware"
func register() {
	handle("POST /api/v1/evm/signers/{address}/unlock", Permitted(middleware.PermUnlockSigner))
}`,
	})
	if len(keys) != 0 {
		t.Errorf("an enforced permission must not be reported dead, got %v", keys)
	}
}

// TestDeadPermissions_HandlerCheckCounts: enforcement is not only route
// registration. A handler calling HasPermission reads the constant, so the
// permission is live even though no route names it.
func TestDeadPermissions_HandlerCheckCounts(t *testing.T) {
	keys := deadPermKeys(t, map[string]string{
		"internal/api/middleware": `package middleware
type Permission string
const PermApproveRequest Permission = "approve_request"
var rolePermissions = map[string]map[Permission]bool{
	"admin": {PermApproveRequest: true},
}`,
		"internal/api/handler/evm": `package evm
import "example.com/m/internal/api/middleware"
func approve(role string) bool {
	return middleware.HasPermission(role, middleware.PermApproveRequest)
}`,
	})
	if len(keys) != 0 {
		t.Errorf("a permission checked inside a handler is live, got %v", keys)
	}
}

// TestDeadPermissions_GrantAloneIsNotUse is the crux of the criterion. The role
// table is what makes a dead permission *look* alive: it appears in a map, in a
// security-relevant file, next to permissions that are genuinely enforced.
// Counting that occurrence as a use would make this check permanently green.
func TestDeadPermissions_GrantAloneIsNotUse(t *testing.T) {
	keys := deadPermKeys(t, map[string]string{
		"internal/api/middleware": `package middleware
type Permission string
const PermApproveSigner Permission = "approve_signer"
var rolePermissions = map[string]map[Permission]bool{
	"admin": {PermApproveSigner: true},
	"dev":   {PermApproveSigner: true},
}`,
	})
	if len(keys) != 1 || keys[0] != "PermApproveSigner" {
		t.Errorf("a permission that is only granted is dead, got %v", keys)
	}
}

// TestDeadPermissions_LostSubjectIsAFinding: if the constants move out of
// internal/api/middleware the check stops being able to see anything. Going
// green there would be the worst outcome — a gate that measures nothing while
// reporting ok. It must say so instead.
func TestDeadPermissions_LostSubjectIsAFinding(t *testing.T) {
	keys := deadPermKeys(t, map[string]string{
		"internal/api": `package api
func nothing() {}`,
	})
	if len(keys) != 1 || keys[0] != "Permission" {
		t.Errorf("losing the subject must be a finding, got %v", keys)
	}
	found, _ := checkDeadPermissions(parseSources(t, map[string]string{
		"internal/api": `package api
func nothing() {}`,
	}))
	if !strings.Contains(found[0].Msg, "lost its subject") {
		t.Errorf("message must explain the check went blind: %s", found[0].Msg)
	}
}
