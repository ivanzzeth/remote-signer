package evm

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
)

// SignAPI defines the signing operations interface.
type SignAPI interface {
	Execute(ctx context.Context, req *SignRequest) (*SignResponse, error)
	ExecuteAsync(ctx context.Context, req *SignRequest) (*SignResponse, error)
}

// RequestAPI defines the request management operations interface.
type RequestAPI interface {
	Get(ctx context.Context, requestID string) (*RequestStatus, error)
	List(ctx context.Context, filter *ListRequestsFilter) (*ListRequestsResponse, error)
	Approve(ctx context.Context, requestID string, req *ApproveRequest) (*ApproveResponse, error)
	PreviewRule(ctx context.Context, requestID string, req *PreviewRuleRequest) (*PreviewRuleResponse, error)
	GetSimulation(ctx context.Context, requestID string) (*SimulateResponse, error)
}

// RuleAPI defines the rule CRUD operations interface.
type RuleAPI interface {
	List(ctx context.Context, filter *ListRulesFilter) (*ListRulesResponse, error)
	Get(ctx context.Context, ruleID string) (*Rule, error)
	Create(ctx context.Context, req *CreateRuleRequest) (*Rule, error)
	Update(ctx context.Context, ruleID string, req *UpdateRuleRequest) (*Rule, error)
	Delete(ctx context.Context, ruleID string) error
	Toggle(ctx context.Context, ruleID string, enabled bool) (*Rule, error)
	ListBudgets(ctx context.Context, ruleID string) ([]RuleBudget, error)
}

// SignerAPI defines the signer management operations interface.
type SignerAPI interface {
	List(ctx context.Context, filter *ListSignersFilter) (*ListSignersResponse, error)
	Create(ctx context.Context, req *CreateSignerRequest) (*Signer, error)
	Unlock(ctx context.Context, address string, req *UnlockSignerRequest) (*UnlockSignerResponse, error)
	Lock(ctx context.Context, address string) (*LockSignerResponse, error)
	PatchSignerLabels(ctx context.Context, address string, req *PatchSignerLabelsRequest) (*Signer, error)
	DeleteSigner(ctx context.Context, address string) error
}

// HDWalletAPI defines the HD wallet management operations interface.
type HDWalletAPI interface {
	Create(ctx context.Context, req *CreateHDWalletRequest) (*HDWalletResponse, error)
	Import(ctx context.Context, req *CreateHDWalletRequest) (*HDWalletResponse, error)
	List(ctx context.Context) (*ListHDWalletsResponse, error)
	DeriveAddress(ctx context.Context, primaryAddr string, req *DeriveAddressRequest) (*DeriveAddressResponse, error)
	ListDerived(ctx context.Context, primaryAddr string) (*ListDerivedAddressesResponse, error)
	GetSigner(ctx context.Context, primaryAddr string, chainID string, index uint32) (*RemoteSigner, error)
	GetSigners(ctx context.Context, primaryAddr string, chainID string, start, count uint32) ([]*RemoteSigner, error)
}

// WalletAPI defines the wallet operations interface.
type WalletAPI interface {
	Create(ctx context.Context, req *CreateWalletRequest) (*Wallet, error)
	Get(ctx context.Context, id string) (*Wallet, error)
	List(ctx context.Context, filter *ListWalletsFilter) (*ListWalletsResponse, error)
	Update(ctx context.Context, id string, req *UpdateWalletRequest) (*Wallet, error)
	Delete(ctx context.Context, id string) error
	AddMember(ctx context.Context, walletID string, req *AddWalletMemberRequest) (*WalletMember, error)
	RemoveMember(ctx context.Context, walletID, signerAddress string) error
	ListMembers(ctx context.Context, walletID string) (*ListWalletMembersResponse, error)
	ListSigners(ctx context.Context, walletID string) ([]Signer, error)
}

// GuardAPI defines the approval guard interface.
type GuardAPI interface {
	Resume(ctx context.Context) error
}

// RemoteSignerAPI defines the interface for creating remote signers.
type RemoteSignerAPI interface {
	NewRemoteSigner(sign *SignService, address common.Address, chainID string) *RemoteSigner
}

// BudgetAPI defines the standalone budget CRUD operations interface.
type BudgetAPI interface {
	List(ctx context.Context, filter *BudgetListFilter) (*ListBudgetsResponse, error)
	Create(ctx context.Context, req *CreateBudgetRequest) (*Budget, error)
	Get(ctx context.Context, id string) (*Budget, error)
	Update(ctx context.Context, id string, req *UpdateBudgetRequest) (*Budget, error)
	Delete(ctx context.Context, id string) error
	Reset(ctx context.Context, id string) (*Budget, error)
}

// TransactionAPI defines the on-chain transaction query interface.
type TransactionAPI interface {
	List(ctx context.Context, filter *ListTransactionsFilter) (*ListTransactionsResponse, error)
	Get(ctx context.Context, id string) (*TransactionRecord, error)
}

// SimulateAPI defines the simulation operations interface.
type SimulateAPI interface {
	Status(ctx context.Context) (*SimulationStatusResponse, error)
	Simulate(ctx context.Context, req *SimulateRequest) (*SimulateResponse, error)
	SimulateBatch(ctx context.Context, req *SimulateBatchRequest) (*SimulateBatchResponse, error)
}

// BroadcastAPI defines the broadcast operations interface.
type BroadcastAPI interface {
	Broadcast(ctx context.Context, req *BroadcastRequest) (*BroadcastResponse, error)
}

// Compile-time interface checks.
var (
	_ SignAPI        = (*SignService)(nil)
	_ RequestAPI     = (*RequestService)(nil)
	_ RuleAPI        = (*RuleService)(nil)
	_ SignerAPI      = (*SignerService)(nil)
	_ HDWalletAPI    = (*HDWalletService)(nil)
	_ GuardAPI       = (*GuardService)(nil)
	_ WalletAPI      = (*WalletService)(nil)
	_ BudgetAPI      = (*BudgetService)(nil)
	_ TransactionAPI = (*TransactionService)(nil)
	_ SimulateAPI    = (*SimulateService)(nil)
	_ BroadcastAPI   = (*BroadcastService)(nil)
)
