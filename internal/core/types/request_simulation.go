// Package types — request_simulation.go is the persistence-side
// model for the simulation engine's most recent evaluation of a
// sign request. The web UI's request-detail page polls
// /api/v1/evm/requests/{id}/simulation against this row, so
// operators see balance changes + decoded events + decision the
// simulation would take *before* they decide whether to manually
// approve.
//
// Cardinality is 1:1 with sign_requests by design — the row's PK
// IS the sign-request id, and re-evaluations Upsert rather than
// inserting new rows. If a request goes through multiple
// simulation ticks (the batch accumulator can fire more than once
// for the same id if a sibling request joins the batch later) the
// latest result wins. The RawResult column keeps the unmodified
// JSON so a future need to re-render or debug can replay the
// historical snapshot.

package types

import (
	"encoding/json"
	"time"
)

// RequestSimulation captures one snapshot of the simulation
// pipeline's view of a sign request. Created lazily by the
// SimulationBudgetRule on first eval, Upserted on each subsequent
// re-eval.
type RequestSimulation struct {
	SignRequestID string `json:"sign_request_id" gorm:"primaryKey;type:varchar(64)"`
	ChainID       string `json:"chain_id" gorm:"index;type:varchar(32)"`

	// Decision is what the simulation engine would tell the sign
	// service if the request were freshly evaluated right now.
	// Values: "allow", "deny", "no_match" (simulation skipped this
	// kind of request — e.g. a sign_type that isn't `transaction`),
	// "manual" (a managed-signer approve / dangerous state change
	// was detected — defer to operator).
	Decision string `json:"decision" gorm:"index;type:varchar(16)"`

	// Reason carries the human-readable explanation when Decision
	// is not "allow" (budget exceeded message, revert reason,
	// approval-detected note, etc.). Empty otherwise.
	Reason string `json:"reason,omitempty" gorm:"type:text"`

	// Result snapshot (success / gas / revert reason). Mirrors the
	// SimulationResult shape so the SDK + UI can render without
	// having to crack open the RawResult blob.
	Success      bool   `json:"success"`
	GasUsed      uint64 `json:"gas_used"`
	RevertReason string `json:"revert_reason,omitempty" gorm:"type:text"`

	// BalanceChanges + Events + Contracts + DecodedCalldata are stored
	// as JSON so we don't have to maintain a separate schema per
	// field shape. The reading side decodes into typed structures
	// at the handler boundary.
	BalanceChanges json.RawMessage `json:"balance_changes,omitempty" gorm:"type:jsonb"`
	Events         json.RawMessage `json:"events,omitempty" gorm:"type:jsonb"`
	Contracts      json.RawMessage `json:"contracts,omitempty" gorm:"type:jsonb"`
	// DecodedCalldata is the parsed (function name + args) view of
	// the transaction's calldata. Empty for sign_types that don't
	// carry calldata (personal_sign, typed_data).
	DecodedCalldata json.RawMessage `json:"decoded_calldata,omitempty" gorm:"type:jsonb"`
	// RawResult is the unmodified SimulationResult JSON — kept as
	// a debug fallback so we can re-render or analyse a past
	// snapshot even after the decoded columns above shift shape.
	RawResult json.RawMessage `json:"raw_result,omitempty" gorm:"type:jsonb"`

	SimulatedAt time.Time `json:"simulated_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TableName matches the migration list in storage/gorm.go.
func (RequestSimulation) TableName() string { return "request_simulations" }
