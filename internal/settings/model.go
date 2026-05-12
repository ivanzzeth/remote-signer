// Package settings hosts the runtime-mutable configuration store. Each tunable
// configuration group lives as a single row in system_settings keyed by a
// stable identifier (e.g. "security", "evm.foundry"); the value is a JSON blob
// matching the corresponding Go snapshot type.
//
// Manager exposes typed accessors (Security(), Foundry(), …) backed by
// *atomic.Pointer snapshots so request-path code can read settings without
// locking. A single background goroutine reloads every snapshot from the DB
// at a fixed cadence so settings written through the admin API or CLI become
// effective without a daemon restart.
package settings

import "time"

// Setting is the GORM row for a single configuration group.
//
// Stability: the schema is forward-compatible — adding fields to a snapshot
// type does not require a migration as long as the JSON is decoded with
// json.Unmarshal (unknown fields are ignored, missing fields take zero
// values). For removing fields, leave the JSON intact and stop reading the
// removed field in code.
type Setting struct {
	Key       string    `gorm:"primaryKey;type:varchar(64)" json:"key"`
	ValueJSON string    `gorm:"type:text;not null"          json:"value_json"`
	UpdatedAt time.Time `                                   json:"updated_at"`
	UpdatedBy string    `gorm:"type:varchar(64)"            json:"updated_by,omitempty"`
}

// TableName pins the GORM table name.
func (Setting) TableName() string { return "system_settings" }

// Group enumerates the well-known configuration groups recognised by Manager.
// Adding a new group means adding a constant here AND a snapshot type with
// the matching JSON shape; Manager will then refresh it like the others.
type Group string

const (
	GroupSecurity      Group = "security"
	GroupNotify        Group = "notify_channels" // populated by the notify_channels typed table, not by this k/v store
	GroupAuditMonitor  Group = "audit_monitor"
	GroupBlocklist     Group = "evm.dynamic_blocklist"
	GroupSimulation    Group = "evm.simulation"
	GroupFoundry       Group = "evm.foundry"
	GroupRPCGateway    Group = "evm.rpc_gateway"
	GroupMaterialCheck Group = "evm.material_check"
)

// Source distinguishes who or what wrote a setting row — useful for audit
// trails and for the one-shot bootstrap that seeds system_settings from a
// fresh config.yaml on the first launch.
const (
	UpdatedBySystem    = "system"
	UpdatedByBootstrap = "bootstrap"
	UpdatedByAPI       = "api"
)
