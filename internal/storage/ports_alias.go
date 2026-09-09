package storage

import (
	"github.com/ivanzzeth/remote-signer/internal/core/ports"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// The repository interfaces and their query shapes are declared by the layer
// that uses them — internal/core/ports — and implemented here.
//
// These aliases exist so that the several hundred existing references to
// storage.RuleRepository and friends keep working, and so there is exactly one
// definition of each type rather than two that can drift. A new caller should
// name ports.RuleRepository directly; the use-case layer must not import this
// package at all.
//
// ⛔ Do not turn any of these back into a definition. X is /usr/bin/X is an
// alias — the same type under two names; X is /usr/bin/X would be a new type,
// and the two would silently stop being interchangeable.
type (
	APIKeyFilter                 = ports.APIKeyFilter
	APIKeyRepository             = ports.APIKeyRepository
	AuditFilter                  = ports.AuditFilter
	AuditRepository              = ports.AuditRepository
	BudgetRepository             = ports.BudgetRepository
	BudgetSyncRequest            = ports.BudgetSyncRequest
	MemoryRuleRepository         = ports.MemoryRuleRepository
	NonceStore                   = ports.NonceStore
	PresetFilter                 = ports.PresetFilter
	PresetRepository             = ports.PresetRepository
	RequestFilter                = ports.RequestFilter
	RequestRepository            = ports.RequestRepository
	RuleFilter                   = ports.RuleFilter
	RuleRepository               = ports.RuleRepository
	SignerAccessRepository       = ports.SignerAccessRepository
	SignerListFilter             = ports.SignerListFilter
	SignerOwnershipRepository    = ports.SignerOwnershipRepository
	SignerOwnershipTransactional = ports.SignerOwnershipTransactional
	SignerRepository             = ports.SignerRepository
	TemplateFilter               = ports.TemplateFilter
	TemplateRepository           = ports.TemplateRepository
	TransactionRepository        = ports.TransactionRepository
	WalletRepository             = ports.WalletRepository
)

// Sentinel errors, re-exported for the same reason as the types above.
var (
	ErrBudgetExceeded = ports.ErrBudgetExceeded
	ErrStateConflict  = ports.ErrStateConflict
)

// SyntheticBudgetRuleID is the sim:<signer> naming rule; see ports.
func SyntheticBudgetRuleID(signerAddress string) types.RuleID {
	return ports.SyntheticBudgetRuleID(signerAddress)
}

// NewMemoryRuleRepository returns an in-memory RuleRepository.
func NewMemoryRuleRepository() *ports.MemoryRuleRepository { return ports.NewMemoryRuleRepository() }
