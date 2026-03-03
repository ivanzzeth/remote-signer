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
}

// RuleAPI defines the rule CRUD operations interface.
type RuleAPI interface {
	List(ctx context.Context, filter *ListRulesFilter) (*ListRulesResponse, error)
	Get(ctx context.Context, ruleID string) (*Rule, error)
	Create(ctx context.Context, req *CreateRuleRequest) (*Rule, error)
	Update(ctx context.Context, ruleID string, req *UpdateRuleRequest) (*Rule, error)
	Delete(ctx context.Context, ruleID string) error
	Toggle(ctx context.Context, ruleID string, enabled bool) (*Rule, error)
}

// SignerAPI defines the signer management operations interface.
type SignerAPI interface {
	List(ctx context.Context, filter *ListSignersFilter) (*ListSignersResponse, error)
	Create(ctx context.Context, req *CreateSignerRequest) (*Signer, error)
	Unlock(ctx context.Context, address string, req *UnlockSignerRequest) (*UnlockSignerResponse, error)
	Lock(ctx context.Context, address string) (*LockSignerResponse, error)
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

// GuardAPI defines the approval guard interface.
type GuardAPI interface {
	Resume(ctx context.Context) error
}

// RemoteSignerAPI defines the interface for creating remote signers.
type RemoteSignerAPI interface {
	NewRemoteSigner(sign *SignService, address common.Address, chainID string) *RemoteSigner
}

// Compile-time interface checks.
var (
	_ SignAPI     = (*SignService)(nil)
	_ RequestAPI  = (*RequestService)(nil)
	_ RuleAPI     = (*RuleService)(nil)
	_ SignerAPI   = (*SignerService)(nil)
	_ HDWalletAPI = (*HDWalletService)(nil)
	_ GuardAPI    = (*GuardService)(nil)
)
