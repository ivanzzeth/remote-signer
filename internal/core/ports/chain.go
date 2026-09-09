package ports

import (
	"context"
	"encoding/json"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ChainRegistry resolves a chain type to its adapter.
//
// types.ChainAdapter is already the domain's idea of a chain; what the
// use-case layer was missing was a way to look one up without naming
// *chain.Registry, the concrete map that holds them.
type ChainRegistry interface {
	Get(chainType types.ChainType) (types.ChainAdapter, error)
	Register(adapter types.ChainAdapter) error
}

// SimulationOutcome is the part of a simulation result the signing path acts
// on: allow, deny, or neither, and why.
//
// ⚠️ The full result — balance deltas, decoded events, gas — belongs to the
// simulation engine and the UI that renders it. SignService reads two fields,
// so this is two fields. Returning the engine's struct would have made every
// caller of the signing path depend on the simulator's shape.
type SimulationOutcome struct {
	// Decision is "allow", "deny", or "" when simulation reached no verdict.
	Decision string
	// Reason explains a deny; empty otherwise.
	Reason string
}

// SimulationBudgetEvaluator is the optional fallback the signing path consults
// when no rule matched: simulate the transaction and see whether it stays
// inside the signer's budget.
//
// Available() exists because the evaluator can be configured but unusable — no
// RPC gateway, no simulator — and the caller must be able to skip it without
// treating that as an error.
type SimulationBudgetEvaluator interface {
	Available() bool
	EvaluateSingle(ctx context.Context, req *types.SignRequest, parsed *types.ParsedPayload) (*SimulationOutcome, error)
}

// HDHierarchyInfo locates a derived signer under its parent HD wallet.
type HDHierarchyInfo struct {
	ParentAddress   string
	DerivationIndex uint32
}

// SignerInventory is what the material checker needs: the signers that exist
// and how derived ones relate to their parents.
//
// ⚠️ Two methods out of SignerManager's ten. The checker asked for the whole
// interface — and so for the package that defines keystores, HD wallets and
// providers — to list signers and read a hierarchy.
type SignerInventory interface {
	ListSigners(ctx context.Context, filter types.SignerFilter) (types.SignerListResult, error)
	GetHDHierarchy() map[string]HDHierarchyInfo
}

// ReceiptFetcher reads a transaction receipt from a chain.
//
// ⚠️ One method out of RPCProvider's surface — which also carries endpoint
// selection, gateway credentials, retry policy and a client cache. The
// transaction recorder polls for a receipt; that is all it needs and all it
// should be coupled to.
//
// A nil receipt with a nil error means "not mined yet", which is a normal
// answer and not a failure.
type ReceiptFetcher interface {
	GetTransactionReceipt(ctx context.Context, chainID, txHash string) (json.RawMessage, error)
}
