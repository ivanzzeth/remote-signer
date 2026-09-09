package ports

import (
	"context"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// RuleRepository defines the interface for rule persistence
type RuleRepository interface {
	Create(ctx context.Context, rule *types.Rule) error
	Get(ctx context.Context, id types.RuleID) (*types.Rule, error)
	Update(ctx context.Context, rule *types.Rule) error
	Delete(ctx context.Context, id types.RuleID) error
	List(ctx context.Context, filter RuleFilter) ([]*types.Rule, error)
	Count(ctx context.Context, filter RuleFilter) (int, error)
	ListByChainType(ctx context.Context, chainType types.ChainType) ([]*types.Rule, error)
	IncrementMatchCount(ctx context.Context, id types.RuleID) error
	// ValidateDelegateRefs checks that all delegate_to and delegate_to_by_target
	// inst_<hash> references in a rule's config exist as rules in the database.
	// This enforces referential integrity for references embedded in the JSONB
	// config column. No-op for rules without delegate references.
	ValidateDelegateRefs(ctx context.Context, rule *types.Rule) error
}

// RuleFilter for querying rules
type RuleFilter struct {
	ChainType     *types.ChainType
	ChainID       *string
	Owner         *string
	SignerAddress *string
	Type          *types.RuleType
	Source        *types.RuleSource
	EnabledOnly   bool
	Offset        int
	Limit         int
}

// BudgetRepository defines the interface for budget persistence
type BudgetRepository interface {
	Create(ctx context.Context, budget *types.RuleBudget) error
	// CreateOrGet atomically creates a budget record or returns the existing one.
	// SECURITY: Uses INSERT ... ON CONFLICT DO NOTHING (upsert) to prevent TOCTOU
	// race conditions where concurrent requests both find "not found" and both try to create.
	// Returns the budget (created or existing) and a bool indicating if it was created (true) or already existed (false).
	CreateOrGet(ctx context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error)
	GetByRuleID(ctx context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error)
	// Get fetches a budget by its primary key. Used by the
	// administrative /budgets/{id} endpoints where the caller already
	// has the deterministic ID (SHA256 of rule_id+unit) rather than the
	// two component fields.
	Get(ctx context.Context, id string) (*types.RuleBudget, error)
	// Update persists changes to mutable fields (max_total, max_per_tx,
	// max_tx_count, alert_pct, alert_sent, spent, tx_count). It does
	// NOT permit changes to id/rule_id/unit/created_at — those define
	// the row's identity and the budget hash.
	Update(ctx context.Context, budget *types.RuleBudget) error
	// UpsertLimits creates or updates budget limit fields for each request.
	// Does NOT touch spent, tx_count, or alert_sent (runtime counters).
	// Uses a single transaction so all units are synced atomically.
	UpsertLimits(ctx context.Context, ruleID types.RuleID, requests []BudgetSyncRequest) error
	// CountByRuleID returns the number of distinct budget units for a rule.
	// SECURITY: Used to enforce MaxDynamicUnits limit to prevent budget amplification attacks.
	CountByRuleID(ctx context.Context, ruleID types.RuleID) (int, error)
	Delete(ctx context.Context, id string) error
	DeleteByRuleID(ctx context.Context, ruleID types.RuleID) error
	// AtomicSpend atomically increments spent amount and tx count.
	// Returns ErrBudgetExceeded if the spend would exceed limits.
	// Uses SQL-level conditional UPDATE to prevent race conditions.
	AtomicSpend(ctx context.Context, ruleID types.RuleID, unit string, amount string) error
	// ResetBudget resets spent/txCount/alertSent for a new period.
	// Uses conditional WHERE to ensure idempotent reset (only resets if in old period).
	ResetBudget(ctx context.Context, ruleID types.RuleID, unit string, currentPeriodStart time.Time) error
	ListByRuleID(ctx context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error)
	ListByRuleIDs(ctx context.Context, ruleIDs []types.RuleID) ([]*types.RuleBudget, error)
	// ListAll returns every budget row, ordered by created_at desc. Used by
	// the operator-facing /budgets list which must surface synthetic
	// simulation budgets (rule_id "sim:0x...") that don't appear in the
	// rules table — fanning out from rules.list() would miss them.
	ListAll(ctx context.Context) ([]*types.RuleBudget, error)
	// MarkAlertSent sets alert_sent=true for the given rule+unit budget.
	// This prevents duplicate alert notifications within the same period.
	MarkAlertSent(ctx context.Context, ruleID types.RuleID, unit string) error
}

// BudgetSyncRequest carries resolved limit values for a single budget unit,
// used when variables change and budget limits must be re-resolved from a template.
type BudgetSyncRequest struct {
	Unit       string
	MaxTotal   string
	MaxPerTx   string
	MaxTxCount int
	AlertPct   int
}

// TemplateRepository defines the interface for template persistence
type TemplateRepository interface {
	Create(ctx context.Context, tmpl *types.RuleTemplate) error
	Get(ctx context.Context, id string) (*types.RuleTemplate, error)
	GetByName(ctx context.Context, name string) (*types.RuleTemplate, error)
	Update(ctx context.Context, tmpl *types.RuleTemplate) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter TemplateFilter) ([]*types.RuleTemplate, error)
	Count(ctx context.Context, filter TemplateFilter) (int, error)
	// Upsert writes tmpl, skipping the DB write when an existing row
	// has the same ContentHash. Returns changed=true when the row was
	// inserted or updated, false when the on-disk content matched the
	// cached one. Used by the Registry's Sync loop to avoid a full
	// JSON re-marshal on every boot.
	Upsert(ctx context.Context, tmpl *types.RuleTemplate) (changed bool, err error)
	// ListIDsBySource returns the IDs of every row whose Source matches
	// the given value. Registry.Sync calls this to compute the set of
	// rows that disappeared from a file source and need pruning.
	ListIDsBySource(ctx context.Context, source types.RuleSource) ([]string, error)
	// DeleteMany removes rows by ID in one statement.
	DeleteMany(ctx context.Context, ids []string) error
}

// TemplateFilter for querying templates
type TemplateFilter struct {
	Type        *types.RuleType
	Source      *types.RuleSource
	EnabledOnly bool
	Offset      int
	Limit       int
}

// PresetRepository defines persistence for rule presets. Mirrors
// TemplateRepository's shape so the Registry can drive both with the
// same Sync algorithm.
type PresetRepository interface {
	Create(ctx context.Context, p *types.RulePreset) error
	Get(ctx context.Context, id string) (*types.RulePreset, error)
	Update(ctx context.Context, p *types.RulePreset) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter PresetFilter) ([]*types.RulePreset, error)
	Count(ctx context.Context, filter PresetFilter) (int, error)
	Upsert(ctx context.Context, p *types.RulePreset) (changed bool, err error)
	ListIDsBySource(ctx context.Context, source types.RuleSource) ([]string, error)
	DeleteMany(ctx context.Context, ids []string) error
}

// PresetFilter for querying presets.
type PresetFilter struct {
	ChainType   *types.ChainType
	Source      *types.RuleSource
	EnabledOnly bool
	Offset      int
	Limit       int
}

// APIKeyRepository defines the interface for API key persistence
type APIKeyRepository interface {
	Create(ctx context.Context, key *types.APIKey) error
	Get(ctx context.Context, id string) (*types.APIKey, error)
	Update(ctx context.Context, key *types.APIKey) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter APIKeyFilter) ([]*types.APIKey, error)
	Count(ctx context.Context, filter APIKeyFilter) (int, error)
	UpdateLastUsed(ctx context.Context, id string) error
	// DeleteBySourceExcluding deletes all keys with the given source whose IDs are NOT in the excludeIDs list.
	DeleteBySourceExcluding(ctx context.Context, source string, excludeIDs []string) (int64, error)
	BackfillSource(ctx context.Context, defaultSource string) (int64, error)
}

// APIKeyFilter for querying API keys
type APIKeyFilter struct {
	EnabledOnly bool
	Source      string // "config", "api", or "" for all
	Offset      int
	Limit       int
}

// NonceStore provides storage for request nonces to prevent replay attacks.
// Nonces are stored with TTL and automatically cleaned up.
type NonceStore interface {
	// CheckAndStore checks if a nonce exists and stores it if not.
	// Returns true if the nonce was stored (new), false if it already exists (replay).
	CheckAndStore(ctx context.Context, apiKeyID, nonce string, ttl time.Duration) (bool, error)
}

// AuditRepository defines the interface for audit log persistence
type AuditRepository interface {
	Log(ctx context.Context, record *types.AuditRecord) error
	Query(ctx context.Context, filter AuditFilter) ([]*types.AuditRecord, error)
	Count(ctx context.Context, filter AuditFilter) (int, error)
	GetByRequestID(ctx context.Context, requestID types.SignRequestID) ([]*types.AuditRecord, error)
	// DeleteOlderThan removes audit records with timestamp before the given time.
	// Returns the number of records deleted.
	DeleteOlderThan(ctx context.Context, before time.Time) (int64, error)
}

// AuditFilter for querying audit records
type AuditFilter struct {
	RequestID         *types.SignRequestID
	APIKeyID          *string
	EventType         *types.AuditEventType
	ExcludeEventTypes []types.AuditEventType
	Severity          *types.AuditSeverity
	ChainType         *types.ChainType
	ChainID           *string
	SignerAddress     *string
	StartTime         *time.Time
	EndTime           *time.Time
	// Cursor-based pagination (preferred over Offset)
	// Cursor is the timestamp of the last item from previous page
	Cursor *time.Time
	// CursorID is the ID of the last item (for tie-breaking when timestamps are equal)
	CursorID *types.AuditID
	Limit    int
}

// RequestRepository defines the interface for sign request persistence
type RequestRepository interface {
	Create(ctx context.Context, req *types.SignRequest) error
	Get(ctx context.Context, id types.SignRequestID) (*types.SignRequest, error)
	Update(ctx context.Context, req *types.SignRequest) error
	// CompareAndUpdate atomically updates a request only if its current status
	// matches expectedStatus. Returns ErrStateConflict if the status has changed.
	CompareAndUpdate(ctx context.Context, req *types.SignRequest, expectedStatus types.SignRequestStatus) error
	List(ctx context.Context, filter RequestFilter) ([]*types.SignRequest, error)
	Count(ctx context.Context, filter RequestFilter) (int, error)
	UpdateStatus(ctx context.Context, id types.SignRequestID, status types.SignRequestStatus) error
	// UpdateLastNoMatchReason records the whitelist engine's diagnostic
	// for "no rule matched" so it surfaces in the API + activity drawer.
	// Best-effort — callers swallow errors because the sign flow has
	// already moved on to manual approval / simulation.
	UpdateLastNoMatchReason(ctx context.Context, id types.SignRequestID, reason string) error
	// LookupBySignedData finds the most recent completed sign request
	// whose SignedData equals the supplied bytes. Used by the wallet
	// RPC proxy to link an eth_sendRawTransaction broadcast back to
	// the request that produced it. Returns ErrNotFound when no
	// match (third-party caller hit the proxy with a payload we
	// didn't sign).
	LookupBySignedData(ctx context.Context, signedData []byte) (*types.SignRequest, error)
	// SetTransactionID stores the FK after the proxy creates a
	// transactions row. Best-effort — sign_request retains its
	// completed status even if the back-ref write fails (the txs
	// table is still the source of truth).
	SetTransactionID(ctx context.Context, id types.SignRequestID, transactionID string) error
}

// RequestFilter for querying requests
type RequestFilter struct {
	APIKeyID      *string
	SignerAddress *string
	ChainType     *types.ChainType
	ChainID       *string
	SignType      *string
	// APIKeyRole filters to requests whose api_key_id belongs to a key
	// with this role (admin-only query param).
	APIKeyRole *types.APIKeyRole
	// TransactionStatus filters by linked on-chain row status.
	// "none" means no transaction_id is set; other values match
	// transactions.status (broadcasted, mined, dropped, failed).
	TransactionStatus *string
	Status            []types.SignRequestStatus
	// Cursor-based pagination (preferred over Offset)
	// Cursor is the created_at timestamp of the last item from previous page
	Cursor *time.Time
	// CursorID is the ID of the last item (for tie-breaking when timestamps are equal)
	CursorID *types.SignRequestID
	Limit    int
}

// SignerAccessRepository manages signer access grants.
type SignerAccessRepository interface {
	Grant(ctx context.Context, access *types.SignerAccess) error
	Revoke(ctx context.Context, signerAddress, apiKeyID string) error
	List(ctx context.Context, signerAddress string) ([]*types.SignerAccess, error)
	HasAccess(ctx context.Context, signerAddress, apiKeyID string) (bool, error)
	HasAccessViaWallet(ctx context.Context, apiKeyID, walletID string) (bool, error)
	DeleteBySigner(ctx context.Context, signerAddress string) error
	DeleteByAPIKey(ctx context.Context, apiKeyID string) error
	ListAccessibleAddresses(ctx context.Context, apiKeyID string) ([]string, error)
}

// SignerOwnershipRepository manages signer ownership records.
type SignerOwnershipRepository interface {
	Upsert(ctx context.Context, ownership *types.SignerOwnership) error
	Get(ctx context.Context, signerAddress string) (*types.SignerOwnership, error)
	// GetBoth atomically fetches ownership records for two addresses.
	// Returns (senderOwnership, recipientOwnership, error).
	// If an address is not found, that ownership will be nil (not an error).
	GetBoth(ctx context.Context, senderAddress, recipientAddress string) (*types.SignerOwnership, *types.SignerOwnership, error)
	GetByOwner(ctx context.Context, ownerID string) ([]*types.SignerOwnership, error)
	// GetByStatus returns all ownership rows in the given status (e.g. pending_approval).
	GetByStatus(ctx context.Context, status types.SignerOwnershipStatus) ([]*types.SignerOwnership, error)
	Delete(ctx context.Context, signerAddress string) error
	UpdateOwner(ctx context.Context, signerAddress, newOwnerID string) error
	CountByOwner(ctx context.Context, ownerID string) (int64, error)
	CountByOwnerAndType(ctx context.Context, ownerID string, signerType types.SignerType) (int64, error)
}

// SignerRepository manages DB-backed signer inventory records.
type SignerRepository interface {
	Upsert(ctx context.Context, signer *types.Signer) error
	Get(ctx context.Context, address string) (*types.Signer, error)
	List(ctx context.Context, filter SignerListFilter) ([]types.Signer, int, error)
	Delete(ctx context.Context, address string) error
	UpdateMaterialStatus(ctx context.Context, address string, status types.SignerMaterialStatus, checkedAt time.Time, missingAt *time.Time, materialErr string) error
}

// TransactionRepository defines the persistence surface the wallet
// RPC proxy + receipt-polling service depend on.
type TransactionRepository interface {
	Create(ctx context.Context, tx *types.Transaction) error
	Get(ctx context.Context, id string) (*types.Transaction, error)
	GetByHash(ctx context.Context, chainID, txHash string) (*types.Transaction, error)
	GetBySignRequestID(ctx context.Context, signRequestID string) (*types.Transaction, error)
	// ListPending returns broadcasted-but-not-yet-mined txs ordered by
	// LastCheckedAt ASC so the poller naturally throttles fresh
	// checks (txs that were recently polled stay at the tail of the
	// queue until they age past the others).
	ListPending(ctx context.Context, limit int) ([]*types.Transaction, error)
	List(ctx context.Context, filter types.TransactionFilter) ([]*types.Transaction, error)
	Count(ctx context.Context, filter types.TransactionFilter) (int, error)
	Update(ctx context.Context, tx *types.Transaction) error
}

// WalletRepository defines the interface for wallet persistence.
type WalletRepository interface {
	Create(ctx context.Context, wallet *types.Wallet) error
	Get(ctx context.Context, id string) (*types.Wallet, error)
	Update(ctx context.Context, wallet *types.Wallet) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter types.WalletFilter) (*types.WalletListResult, error)

	AddMember(ctx context.Context, member *types.WalletMember) error
	RemoveMember(ctx context.Context, walletID, signerAddress string) error
	ListMembers(ctx context.Context, walletID string) ([]types.WalletMember, error)
	IsMember(ctx context.Context, walletID, signerAddress string) (bool, error)

	// GetWalletsForSigner returns all wallets that contain the given signer.
	GetWalletsForSigner(ctx context.Context, signerAddress string) ([]types.Wallet, error)
	// GetWalletsForSigners returns signer-address to wallets mapping in batch.
	GetWalletsForSigners(ctx context.Context, signerAddresses []string) (map[string][]types.Wallet, error)
}

// SignerListFilter defines list filters for DB signers.
type SignerListFilter struct {
	Type   *types.SignerType
	Offset int
	Limit  int
}

// SignerOwnershipTransactional is implemented by ownership repos that support atomic operations
// spanning both ownership and access repos within a single DB transaction.
type SignerOwnershipTransactional interface {
	RunInTransaction(ctx context.Context, fn func(txOwnership SignerOwnershipRepository, txAccess SignerAccessRepository) error) error
}

// SignAuditSink is what the signing service needs from an audit log: somewhere
// to record that a request was made and that it went to approval.
//
// ⚠️ Two methods, not the audit logger's full surface. The service asked for
// *audit.AuditLogger before, so it depended on an adapter — and on the thirty
// other methods that type has — to call two. A port describes what the caller
// needs; the implementation is free to be larger.
//
// Nil is a legal value at the call site: audit logging is optional, and a
// service that panics without it would make the logger mandatory by accident.
type SignAuditSink interface {
	LogSignRequest(ctx context.Context, req *types.SignRequest)
	LogApprovalRequest(ctx context.Context, req *types.SignRequest)
}
