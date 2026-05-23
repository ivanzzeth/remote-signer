package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ivanzzeth/ethsig/eip712"
)

func TestNewService(t *testing.T) {
	srv, tr := testServer(t, staticHandler(http.StatusOK, nil))
	defer srv.Close()

	svc := NewService(tr)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	if svc.Sign == nil {
		t.Fatal("expected non-nil Sign")
	}
	if svc.Requests == nil {
		t.Fatal("expected non-nil Requests")
	}
	if svc.Rules == nil {
		t.Fatal("expected non-nil Rules")
	}
	if svc.Signers == nil {
		t.Fatal("expected non-nil Signers")
	}
	if svc.HDWallets == nil {
		t.Fatal("expected non-nil HDWallets")
	}
	if svc.Guard == nil {
		t.Fatal("expected non-nil Guard")
	}
	if svc.Simulate == nil {
		t.Fatal("expected non-nil Simulate")
	}
	if svc.Broadcast == nil {
		t.Fatal("expected non-nil Broadcast")
	}
	if svc.Wallets == nil {
		t.Fatal("expected non-nil Wallets")
	}
}

func TestSetPolling(t *testing.T) {
	svc := &SignService{}
	svc.SetPolling(500*time.Millisecond, 30*time.Second)
	if svc.PollInterval != 500*time.Millisecond {
		t.Fatalf("PollInterval = %v", svc.PollInterval)
	}
	if svc.PollTimeout != 30*time.Second {
		t.Fatalf("PollTimeout = %v", svc.PollTimeout)
	}
}

func TestExecuteAsync(t *testing.T) {
	signResp := SignResponse{
		RequestID: "async-1",
		Status:    StatusPending,
		Message:   "pending",
	}
	srv, tr := testServer(t, jsonHandler(http.StatusAccepted, signResp))
	defer srv.Close()

	svc := &SignService{transport: tr}
	resp, err := svc.ExecuteAsync(context.Background(), &SignRequest{
		ChainID:       "1",
		SignerAddress: "0xabc",
		SignType:      SignTypeHash,
		Payload:       json.RawMessage(`{"hash":"0xdead"}`),
	})
	if err == nil {
		t.Fatal("expected error for pending async")
	}
	if resp == nil {
		t.Fatal("expected non-nil response even with error")
	}
	if resp.RequestID != "async-1" {
		t.Fatalf("RequestID = %s", resp.RequestID)
	}
}

func TestExecuteAsyncCompleted(t *testing.T) {
	signResp := SignResponse{
		RequestID: "async-2",
		Status:    StatusCompleted,
		Signature: "0xsig",
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, signResp))
	defer srv.Close()

	svc := &SignService{transport: tr}
	resp, err := svc.ExecuteAsync(context.Background(), &SignRequest{
		ChainID:       "1",
		SignerAddress: "0xabc",
		SignType:      SignTypeHash,
		Payload:       json.RawMessage(`{"hash":"0xdead"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.RequestID != "async-2" {
		t.Fatalf("RequestID = %s", resp.RequestID)
	}
}

func TestExecuteRejected(t *testing.T) {
	signResp := SignResponse{
		RequestID: "rej-1",
		Status:    StatusRejected,
		Message:   "rejected by admin",
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, signResp))
	defer srv.Close()

	svc := &SignService{transport: tr}
	_, err := svc.Execute(context.Background(), &SignRequest{
		ChainID:       "1",
		SignerAddress: "0xabc",
		SignType:      SignTypeHash,
		Payload:       json.RawMessage(`{"hash":"0xdead"}`),
	})
	if err == nil {
		t.Fatal("expected error")
	}
	var signErr *SignError
	if !errors.As(err, &signErr) {
		t.Fatalf("error type = %T", err)
	}
	if signErr.Status != StatusRejected {
		t.Fatalf("Status = %s", signErr.Status)
	}
}

func TestExecuteFailed(t *testing.T) {
	signResp := SignResponse{
		RequestID: "fail-1",
		Status:    StatusFailed,
		Message:   "internal error",
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, signResp))
	defer srv.Close()

	svc := &SignService{transport: tr}
	_, err := svc.Execute(context.Background(), &SignRequest{
		ChainID:       "1",
		SignerAddress: "0xabc",
		SignType:      SignTypeHash,
		Payload:       json.RawMessage(`{"hash":"0xdead"}`),
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSignErrorIsPendingApproval(t *testing.T) {
	err := &SignError{Status: StatusAuthorizing}
	if !err.Is(ErrPendingApproval) {
		t.Fatal("should match ErrPendingApproval")
	}
	if err.Is(ErrRejected) {
		t.Fatal("should not match ErrRejected")
	}
}

func TestSignErrorIsRejected(t *testing.T) {
	err := &SignError{Status: StatusRejected}
	if !err.Is(ErrRejected) {
		t.Fatal("should match ErrRejected")
	}
	if err.Is(ErrPendingApproval) {
		t.Fatal("should not match ErrPendingApproval")
	}
}

func TestSignErrorIsUnknown(t *testing.T) {
	err := &SignError{Status: StatusCompleted}
	if err.Is(ErrPendingApproval) {
		t.Fatal("should not match ErrPendingApproval")
	}
	if err.Is(ErrRejected) {
		t.Fatal("should not match ErrRejected")
	}
}

func TestSignErrorStringWithRequestID(t *testing.T) {
	err := &SignError{RequestID: "req-1", Status: StatusRejected, Message: "nope"}
	s := err.Error()
	if s != "sign error [req-1] status=rejected: nope" {
		t.Fatalf("unexpected error string: %s", s)
	}
}

func TestSignErrorStringWithoutRequestID(t *testing.T) {
	err := &SignError{Status: StatusFailed, Message: "boom"}
	s := err.Error()
	if s != "sign error status=failed: boom" {
		t.Fatalf("unexpected error string: %s", s)
	}
}

func TestPollForResultTimeout(t *testing.T) {
	srv, tr := testServer(t, jsonHandler(http.StatusOK, RequestStatus{
		ID:     "req-poll",
		Status: StatusAuthorizing,
	}))
	defer srv.Close()

	svc := &SignService{
		transport:    tr,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  50 * time.Millisecond,
	}
	_, err := svc.pollForResult(context.Background(), "req-poll")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if err != ErrTimeout {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPollForResultCompleted(t *testing.T) {
	completedAt := time.Now()
	sig := "0x" + hex.EncodeToString(make([]byte, 65))
	ruleID := "rule-1"
	srv, tr := testServer(t, jsonHandler(http.StatusOK, RequestStatus{
		ID:            "req-poll-done",
		Status:        StatusCompleted,
		Signature:     sig,
		SignedData:    "0xdead",
		RuleMatchedID: &ruleID,
		CompletedAt:   &completedAt,
	}))
	defer srv.Close()

	svc := &SignService{
		transport:    tr,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  5 * time.Second,
	}
	resp, err := svc.pollForResult(context.Background(), "req-poll-done")
	if err != nil {
		t.Fatal(err)
	}
	if resp.RequestID != "req-poll-done" {
		t.Fatalf("RequestID = %s", resp.RequestID)
	}
	if resp.RuleMatched != "rule-1" {
		t.Fatalf("RuleMatched = %s", resp.RuleMatched)
	}
}

func TestPollForResultRejected(t *testing.T) {
	srv, tr := testServer(t, jsonHandler(http.StatusOK, RequestStatus{
		ID:           "req-poll-rej",
		Status:       StatusRejected,
		ErrorMessage: "denied",
	}))
	defer srv.Close()

	svc := &SignService{
		transport:    tr,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  5 * time.Second,
	}
	_, err := svc.pollForResult(context.Background(), "req-poll-rej")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPollForResultFailed(t *testing.T) {
	srv, tr := testServer(t, jsonHandler(http.StatusOK, RequestStatus{
		ID:           "req-poll-fail",
		Status:       StatusFailed,
		ErrorMessage: "something went wrong",
	}))
	defer srv.Close()

	svc := &SignService{
		transport:    tr,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  5 * time.Second,
	}
	_, err := svc.pollForResult(context.Background(), "req-poll-fail")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSignExecuteBatch(t *testing.T) {
	batchResp := BatchSignResponse{
		Results: []BatchSignResultDTO{
			{Index: 0, RequestID: "br-1", Signature: "0xsig1"},
			{Index: 1, RequestID: "br-2", Signature: "0xsig2"},
		},
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, batchResp))
	defer srv.Close()

	svc := &SignService{transport: tr}
	resp, err := svc.ExecuteBatch(context.Background(), &BatchSignRequest{
		Requests: []BatchSignItemRequest{
			{ChainID: "1", SignerAddress: "0xabc", SignType: "transaction", Transaction: json.RawMessage(`{}`)},
			{ChainID: "1", SignerAddress: "0xabc", SignType: "transaction", Transaction: json.RawMessage(`{}`)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("len results = %d", len(resp.Results))
	}
	if resp.Results[0].Signature != "0xsig1" {
		t.Fatalf("sig = %s", resp.Results[0].Signature)
	}
}

func TestSignExecuteBatchError(t *testing.T) {
	srv, tr := testServer(t, staticHandler(http.StatusBadRequest, []byte(`{"error":"bad_request","message":"invalid"}`)))
	defer srv.Close()

	svc := &SignService{transport: tr}
	_, err := svc.ExecuteBatch(context.Background(), &BatchSignRequest{
		Requests: []BatchSignItemRequest{
			{ChainID: "1", SignerAddress: "0xabc", SignType: "transaction", Transaction: json.RawMessage(`{}`)},
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRequestServiceGet(t *testing.T) {
	now := time.Now()
	status := RequestStatus{
		ID:            "req-get-1",
		Status:        StatusCompleted,
		ChainType:     "evm",
		ChainID:       "1",
		SignerAddress: "0xabc",
		SignType:      SignTypeHash,
		CreatedAt:     now,
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, status))
	defer srv.Close()

	svc := &RequestService{transport: tr}
	got, err := svc.Get(context.Background(), "req-get-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "req-get-1" {
		t.Fatalf("ID = %s", got.ID)
	}
	if got.Status != StatusCompleted {
		t.Fatalf("Status = %s", got.Status)
	}
}

func TestRequestServiceGetNotFound(t *testing.T) {
	srv, tr := testServer(t, staticHandler(http.StatusNotFound, []byte(`{"error":"not_found","message":"request not found"}`)))
	defer srv.Close()

	svc := &RequestService{transport: tr}
	_, err := svc.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSimulateServiceStatus(t *testing.T) {
	statusResp := SimulationStatusResponse{
		Enabled:       true,
		EngineVersion: "v1.0",
		Chains: map[string]ChainStatusDTO{
			"1": {Status: "ready", Port: 8545, BlockNumber: "12345"},
		},
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, statusResp))
	defer srv.Close()

	svc := &SimulateService{transport: tr}
	resp, err := svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Enabled {
		t.Fatal("expected enabled")
	}
	if resp.EngineVersion != "v1.0" {
		t.Fatalf("EngineVersion = %s", resp.EngineVersion)
	}
	if len(resp.Chains) != 1 {
		t.Fatalf("chains = %d", len(resp.Chains))
	}
}

func TestSimulateServiceBatch(t *testing.T) {
	batchResp := SimulateBatchResponse{
		Results: []SimulateResultDTO{
			{Index: 0, Success: true, GasUsed: 21000},
		},
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, batchResp))
	defer srv.Close()

	svc := &SimulateService{transport: tr}
	resp, err := svc.SimulateBatch(context.Background(), &SimulateBatchRequest{
		ChainID: "1",
		From:    "0xfrom",
		Transactions: []SimulateTxDTO{
			{To: "0xto", Value: "0"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("len results = %d", len(resp.Results))
	}
	if !resp.Results[0].Success {
		t.Fatal("expected success")
	}
}

func TestWalletServiceCreate(t *testing.T) {
	wallet := Wallet{
		ID:   "w-create",
		Name: "new-wallet",
	}
	srv, tr := testServer(t, jsonHandler(http.StatusCreated, wallet))
	defer srv.Close()

	svc := &WalletService{transport: tr}
	got, err := svc.Create(context.Background(), &CreateWalletRequest{Name: "new-wallet"})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "w-create" {
		t.Fatalf("ID = %s", got.ID)
	}
}

func TestWalletServiceList(t *testing.T) {
	listResp := ListWalletsResponse{
		Wallets: []Wallet{
			{ID: "w-1", Name: "wallet-1"},
			{ID: "w-2", Name: "wallet-2"},
		},
		Total:   2,
		HasMore: false,
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, listResp))
	defer srv.Close()

	svc := &WalletService{transport: tr}
	resp, err := svc.List(context.Background(), &ListWalletsFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Wallets) != 2 {
		t.Fatalf("len wallets = %d", len(resp.Wallets))
	}
	if resp.Wallets[0].Name != "wallet-1" {
		t.Fatalf("name = %s", resp.Wallets[0].Name)
	}
}

func TestWalletServiceListNilFilter(t *testing.T) {
	listResp := ListWalletsResponse{
		Wallets: []Wallet{},
		Total:   0,
		HasMore: false,
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, listResp))
	defer srv.Close()

	svc := &WalletService{transport: tr}
	resp, err := svc.List(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Wallets) != 0 {
		t.Fatalf("len wallets = %d", len(resp.Wallets))
	}
}

func TestWalletServiceDelete(t *testing.T) {
	srv, tr := testServer(t, staticHandler(http.StatusNoContent, nil))
	defer srv.Close()

	svc := &WalletService{transport: tr}
	if err := svc.Delete(context.Background(), "w-del"); err != nil {
		t.Fatal(err)
	}
}

func TestWalletServiceRemoveMember(t *testing.T) {
	srv, tr := testServer(t, staticHandler(http.StatusOK, nil))
	defer srv.Close()

	svc := &WalletService{transport: tr}
	if err := svc.RemoveMember(context.Background(), "w-1", "0xsig"); err != nil {
		t.Fatal(err)
	}
}

func TestWalletServiceListMembers(t *testing.T) {
	membersResp := ListWalletMembersResponse{
		Members: []WalletMember{
			{WalletID: "w-1", SignerAddress: "0xabc"},
		},
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, membersResp))
	defer srv.Close()

	svc := &WalletService{transport: tr}
	resp, err := svc.ListMembers(context.Background(), "w-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Members) != 1 {
		t.Fatalf("len members = %d", len(resp.Members))
	}
}

func TestHDWalletServiceImport(t *testing.T) {
	walletResp := HDWalletResponse{
		PrimaryAddress: "0ximported",
		BasePath:       "m/44'/60'/0'",
		Locked:         false,
	}
	srv, tr := testServer(t, jsonHandler(http.StatusCreated, walletResp))
	defer srv.Close()

	svc := &HDWalletService{transport: tr, sign: &SignService{transport: tr}}
	got, err := svc.Import(context.Background(), &CreateHDWalletRequest{
		Password: "test",
		Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.PrimaryAddress != "0ximported" {
		t.Fatalf("PrimaryAddress = %s", got.PrimaryAddress)
	}
}

func TestHDWalletServiceList(t *testing.T) {
	listResp := ListHDWalletsResponse{
		Wallets: []HDWalletResponse{
			{PrimaryAddress: "0xhd-1", BasePath: "m/44'/60'/0'"},
		},
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, listResp))
	defer srv.Close()

	svc := &HDWalletService{transport: tr, sign: &SignService{transport: tr}}
	resp, err := svc.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Wallets) != 1 {
		t.Fatalf("len wallets = %d", len(resp.Wallets))
	}
}

func TestHDWalletServiceDeriveAddress(t *testing.T) {
	deriveResp := DeriveAddressResponse{
		Derived: []SignerInfo{
			{Address: "0xderived-1", Type: "hd_derived", Enabled: true},
		},
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, deriveResp))
	defer srv.Close()

	svc := &HDWalletService{transport: tr, sign: &SignService{transport: tr}}
	idx := uint32(1)
	resp, err := svc.DeriveAddress(context.Background(), "0xprimary", &DeriveAddressRequest{Index: &idx})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Derived) != 1 {
		t.Fatalf("len derived = %d", len(resp.Derived))
	}
	if resp.Derived[0].Address != "0xderived-1" {
		t.Fatalf("address = %s", resp.Derived[0].Address)
	}
}

func TestHDWalletServiceListDerived(t *testing.T) {
	listDerived := ListDerivedAddressesResponse{
		Derived: []SignerInfo{
			{Address: "0xderived-1", Type: "hd_derived", Enabled: true},
			{Address: "0xderived-2", Type: "hd_derived", Enabled: false},
		},
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, listDerived))
	defer srv.Close()

	svc := &HDWalletService{transport: tr, sign: &SignService{transport: tr}}
	resp, err := svc.ListDerived(context.Background(), "0xprimary")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Derived) != 2 {
		t.Fatalf("len derived = %d", len(resp.Derived))
	}
}

func TestHDWalletServiceGetSigner(t *testing.T) {
	deriveResp := DeriveAddressResponse{
		Derived: []SignerInfo{
			{Address: "0xabcdef1234567890abcdef1234567890abcdef12", Type: "hd_derived", Enabled: true},
		},
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, deriveResp))
	defer srv.Close()

	svc := &HDWalletService{transport: tr, sign: &SignService{transport: tr}}
	signer, err := svc.GetSigner(context.Background(), "0xprimary", "1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
	if signer.GetAddress() != common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12") {
		t.Fatalf("address = %s", signer.GetAddress().Hex())
	}
}

func TestHDWalletServiceGetSignerEmptyDerived(t *testing.T) {
	deriveResp := DeriveAddressResponse{
		Derived: []SignerInfo{},
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, deriveResp))
	defer srv.Close()

	svc := &HDWalletService{transport: tr, sign: &SignService{transport: tr}}
	_, err := svc.GetSigner(context.Background(), "0xprimary", "1", 0)
	if err == nil {
		t.Fatal("expected error for empty derived")
	}
}

func TestHDWalletServiceGetSigners(t *testing.T) {
	deriveResp := DeriveAddressResponse{
		Derived: []SignerInfo{
			{Address: "0xabcdef1234567890abcdef1234567890abcdef12", Type: "hd_derived", Enabled: true},
			{Address: "0x1234567890abcdef1234567890abcdef12345678", Type: "hd_derived", Enabled: true},
		},
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, deriveResp))
	defer srv.Close()

	svc := &HDWalletService{transport: tr, sign: &SignService{transport: tr}}
	signers, err := svc.GetSigners(context.Background(), "0xprimary", "1", 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 2 {
		t.Fatalf("len signers = %d", len(signers))
	}
}

// TestRemoteSignerChainID tests ChainID and SetChainID on RemoteSigner.
func TestRemoteSignerChainID(t *testing.T) {
	rs := &RemoteSigner{chainID: "1"}
	if rs.ChainID() != "1" {
		t.Fatalf("ChainID = %s", rs.ChainID())
	}
	rs.SetChainID("137")
	if rs.ChainID() != "137" {
		t.Fatalf("ChainID after SetChainID = %s", rs.ChainID())
	}
}

// TestRemoteSignerClose tests that Close is a no-op.
func TestRemoteSignerClose(t *testing.T) {
	rs := &RemoteSigner{}
	if err := rs.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestSignerServiceUnlock tests the Unlock method.
func TestSignerServiceUnlock(t *testing.T) {
	unlockedResp := Signer{
		Address: "0xabc",
		Type:    "keystore",
		Enabled: true,
		Locked:  false,
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, unlockedResp))
	defer srv.Close()

	svc := &SignerService{transport: tr}
	resp, err := svc.Unlock(context.Background(), "0xabc", &UnlockSignerRequest{Password: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Address != "0xabc" {
		t.Fatalf("Address = %s", resp.Address)
	}
	if resp.Locked {
		t.Fatal("expected unlocked")
	}
}

// TestSignerServiceLock tests the Lock method.
func TestSignerServiceLock(t *testing.T) {
	lockedResp := Signer{
		Address: "0xabc",
		Type:    "keystore",
		Enabled: false,
		Locked:  true,
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, lockedResp))
	defer srv.Close()

	svc := &SignerService{transport: tr}
	resp, err := svc.Lock(context.Background(), "0xabc")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Locked {
		t.Fatal("expected locked")
	}
}

// TestSignerServiceApproveSigner tests the ApproveSigner method.
func TestSignerServiceApproveSigner(t *testing.T) {
	srv, tr := testServer(t, staticHandler(http.StatusOK, nil))
	defer srv.Close()

	svc := &SignerService{transport: tr}
	if err := svc.ApproveSigner(context.Background(), "0xabc"); err != nil {
		t.Fatal(err)
	}
}

// TestSignerServiceGrantAccess tests the GrantAccess method.
func TestSignerServiceGrantAccess(t *testing.T) {
	srv, tr := testServer(t, staticHandler(http.StatusOK, nil))
	defer srv.Close()

	svc := &SignerService{transport: tr}
	if err := svc.GrantAccess(context.Background(), "0xabc", &GrantAccessRequest{APIKeyID: "key-2"}); err != nil {
		t.Fatal(err)
	}
}

// TestSignerServiceRevokeAccess tests the RevokeAccess method.
func TestSignerServiceRevokeAccess(t *testing.T) {
	srv, tr := testServer(t, staticHandler(http.StatusOK, nil))
	defer srv.Close()

	svc := &SignerService{transport: tr}
	if err := svc.RevokeAccess(context.Background(), "0xabc", "key-2"); err != nil {
		t.Fatal(err)
	}
}

// TestSignerServiceListAccess tests the ListAccess method.
func TestSignerServiceListAccess(t *testing.T) {
	now := time.Now()
	entries := []SignerAccessEntry{
		{APIKeyID: "key-2", GrantedBy: "key-1", CreatedAt: now},
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, entries))
	defer srv.Close()

	svc := &SignerService{transport: tr}
	resp, err := svc.ListAccess(context.Background(), "0xabc")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != 1 {
		t.Fatalf("len = %d", len(resp))
	}
	if resp[0].APIKeyID != "key-2" {
		t.Fatalf("APIKeyID = %s", resp[0].APIKeyID)
	}
}

// TestSignerServiceTransferOwnership tests the TransferOwnership method.
func TestSignerServiceTransferOwnership(t *testing.T) {
	srv, tr := testServer(t, staticHandler(http.StatusOK, nil))
	defer srv.Close()

	svc := &SignerService{transport: tr}
	if err := svc.TransferOwnership(context.Background(), "0xabc", &TransferOwnershipRequest{NewOwnerID: "key-3"}); err != nil {
		t.Fatal(err)
	}
}

// TestSignerServiceDeleteSigner tests the DeleteSigner method.
func TestSignerServiceDeleteSigner(t *testing.T) {
	srv, tr := testServer(t, staticHandler(http.StatusNoContent, nil))
	defer srv.Close()

	svc := &SignerService{transport: tr}
	if err := svc.DeleteSigner(context.Background(), "0xabc"); err != nil {
		t.Fatal(err)
	}
}

// TestSignerServicePatchSignerLabels tests the PatchSignerLabels method.
func TestSignerServicePatchSignerLabels(t *testing.T) {
	patched := Signer{
		Address:     "0xabc",
		DisplayName: "updated-name",
		Tags:        []string{"tag1", "tag2"},
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, patched))
	defer srv.Close()

	svc := &SignerService{transport: tr}
	newName := "updated-name"
	newTags := []string{"tag1", "tag2"}
	got, err := svc.PatchSignerLabels(context.Background(), "0xabc", &PatchSignerLabelsRequest{
		DisplayName: &newName,
		Tags:        &newTags,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.DisplayName != "updated-name" {
		t.Fatalf("DisplayName = %s", got.DisplayName)
	}
}

// TestRuleServiceList tests the rule List method with filters.
func TestRuleServiceList(t *testing.T) {
	listResp := ListRulesResponse{
		Rules: []Rule{
			{ID: "r-1", Name: "rule-1", Type: "address_list", Mode: "whitelist"},
		},
		Total: 1,
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, listResp))
	defer srv.Close()

	svc := &RuleService{transport: tr}
	enabled := true
	resp, err := svc.List(context.Background(), &ListRulesFilter{
		ChainType:     "evm",
		SignerAddress: "0xabc",
		APIKeyID:      "key-1",
		Type:          "address_list",
		Mode:          "whitelist",
		Enabled:       &enabled,
		Limit:         10,
		Offset:        0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Rules) != 1 {
		t.Fatalf("len rules = %d", len(resp.Rules))
	}
}

// TestRuleServiceListNilFilter tests rule List with a nil filter.
func TestRuleServiceListNilFilter(t *testing.T) {
	listResp := ListRulesResponse{
		Rules: []Rule{},
		Total: 0,
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, listResp))
	defer srv.Close()

	svc := &RuleService{transport: tr}
	resp, err := svc.List(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Rules) != 0 {
		t.Fatalf("len rules = %d", len(resp.Rules))
	}
}

// TestRuleServiceCreate tests rule creation.
func TestRuleServiceCreate(t *testing.T) {
	created := Rule{ID: "r-new", Name: "new-rule", Type: "value_limit", Mode: "whitelist"}
	srv, tr := testServer(t, jsonHandler(http.StatusCreated, created))
	defer srv.Close()

	svc := &RuleService{transport: tr}
	got, err := svc.Create(context.Background(), &CreateRuleRequest{
		Name: "new-rule",
		Type: "value_limit",
		Mode: "whitelist",
		Config: map[string]interface{}{
			"max_value": "1000",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "r-new" {
		t.Fatalf("ID = %s", got.ID)
	}
}

// TestRuleServiceUpdate tests rule update.
func TestRuleServiceUpdate(t *testing.T) {
	updated := Rule{ID: "r-1", Name: "updated-rule", Type: "address_list", Mode: "whitelist"}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, updated))
	defer srv.Close()

	svc := &RuleService{transport: tr}
	got, err := svc.Update(context.Background(), "r-1", &UpdateRuleRequest{
		Name: "updated-rule",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "updated-rule" {
		t.Fatalf("Name = %s", got.Name)
	}
}

// TestRuleServiceDelete tests rule deletion.
func TestRuleServiceDelete(t *testing.T) {
	srv, tr := testServer(t, staticHandler(http.StatusNoContent, nil))
	defer srv.Close()

	svc := &RuleService{transport: tr}
	if err := svc.Delete(context.Background(), "r-del"); err != nil {
		t.Fatal(err)
	}
}

// TestRuleServiceApprove tests rule approve.
func TestRuleServiceApprove(t *testing.T) {
	approved := Rule{ID: "r-pending", Name: "approved-rule", Status: "active"}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, approved))
	defer srv.Close()

	svc := &RuleService{transport: tr}
	got, err := svc.Approve(context.Background(), "r-pending")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "r-pending" {
		t.Fatalf("ID = %s", got.ID)
	}
}

// TestRuleServiceReject tests rule reject.
func TestRuleServiceReject(t *testing.T) {
	rejected := Rule{ID: "r-pending", Name: "rejected-rule", Status: "rejected"}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, rejected))
	defer srv.Close()

	svc := &RuleService{transport: tr}
	got, err := svc.Reject(context.Background(), "r-pending", "not needed")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "r-pending" {
		t.Fatalf("ID = %s", got.ID)
	}
}

// TestRuleServiceValidate tests rule validate.
func TestRuleServiceValidate(t *testing.T) {
	validateResp := ValidateRuleResponse{
		RuleID:   "r-1",
		RuleName: "test-rule",
		Type:     "evm_js",
		Valid:    true,
		Results: []ValidateTestResult{
			{Name: "test-1", Passed: true, ActualPass: true},
		},
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, validateResp))
	defer srv.Close()

	svc := &RuleService{transport: tr}
	resp, err := svc.Validate(context.Background(), "r-1")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Valid {
		t.Fatal("expected valid")
	}
}

// TestRuleServiceBatchValidate tests batch validate.
func TestRuleServiceBatchValidate(t *testing.T) {
	batchResp := BatchValidateResponse{
		Results: []ValidateRuleResponse{
			{RuleID: "r-1", RuleName: "rule-1", Valid: true},
		},
		Total:  1,
		Passed: 1,
		Failed: 0,
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, batchResp))
	defer srv.Close()

	svc := &RuleService{transport: tr}
	resp, err := svc.BatchValidate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Total != 1 {
		t.Fatalf("Total = %d", resp.Total)
	}
}

// TestRemoteSigner_SignRawMessage tests RemoteSigner's SignRawMessage.
func TestRemoteSigner_SignRawMessage(t *testing.T) {
	expectedSig := make([]byte, 65)
	for i := range expectedSig {
		expectedSig[i] = byte(i)
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, SignResponse{
		RequestID: "req-raw",
		Status:    StatusCompleted,
		Signature: "0x" + hex.EncodeToString(expectedSig),
	}))
	defer srv.Close()

	signer := &RemoteSigner{
		sign:    &SignService{transport: tr},
		address: common.HexToAddress("0x1234"),
		chainID: "1",
	}
	sig, err := signer.SignRawMessage([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 65 {
		t.Fatalf("len sig = %d", len(sig))
	}
}

// TestRemoteSigner_SignHash tests RemoteSigner's SignHash.
func TestRemoteSigner_SignHash(t *testing.T) {
	expectedSig := make([]byte, 65)
	hash := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

	srv, tr := testServer(t, jsonHandler(http.StatusOK, SignResponse{
		RequestID: "req-hash",
		Status:    StatusCompleted,
		Signature: "0x" + hex.EncodeToString(expectedSig),
	}))
	defer srv.Close()

	signer := &RemoteSigner{
		sign:    &SignService{transport: tr},
		address: common.HexToAddress("0x1234"),
		chainID: "1",
	}
	sig, err := signer.SignHash(hash)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 65 {
		t.Fatalf("len sig = %d", len(sig))
	}
}

// TestRemoteSigner_SignEIP191 tests RemoteSigner's SignEIP191Message.
func TestRemoteSigner_SignEIP191(t *testing.T) {
	expectedSig := make([]byte, 65)
	srv, tr := testServer(t, jsonHandler(http.StatusOK, SignResponse{
		RequestID: "req-eip191",
		Status:    StatusCompleted,
		Signature: "0x" + hex.EncodeToString(expectedSig),
	}))
	defer srv.Close()

	signer := &RemoteSigner{
		sign:    &SignService{transport: tr},
		address: common.HexToAddress("0x1234"),
		chainID: "1",
	}
	sig, err := signer.SignEIP191Message("hello world")
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 65 {
		t.Fatalf("len sig = %d", len(sig))
	}
}

// TestRemoteSigner_EmptySignature tests error handling for empty signature.
func TestRemoteSigner_EmptySignature(t *testing.T) {
	srv, tr := testServer(t, jsonHandler(http.StatusOK, SignResponse{
		RequestID: "req-empty",
		Status:    StatusCompleted,
		Signature: "",
	}))
	defer srv.Close()

	signer := &RemoteSigner{
		sign:    &SignService{transport: tr},
		address: common.HexToAddress("0x1234"),
		chainID: "1",
	}
	_, err := signer.SignHash(common.HexToHash("0x1234"))
	if err == nil {
		t.Fatal("expected error for empty signature")
	}
}

// TestRemoteSigner_Base64Signature tests decoding a base64-encoded signature.
func TestRemoteSigner_Base64Signature(t *testing.T) {
	sig := make([]byte, 65)
	for i := range sig {
		sig[i] = byte(i)
	}
	// Return base64-encoded signature without 0x prefix
	// This is base64 of bytes 0..64 (65 bytes)
	srv, tr := testServer(t, jsonHandler(http.StatusOK, SignResponse{
		RequestID: "req-b64",
		Status:    StatusCompleted,
		Signature: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=",
	}))
	defer srv.Close()

	signer := &RemoteSigner{
		sign:    &SignService{transport: tr},
		address: common.HexToAddress("0x1234"),
		chainID: "1",
	}
	result, err := signer.SignHash(common.HexToHash("0xdead"))
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 65 {
		t.Fatalf("len result = %d", len(result))
	}
}

// TestRequestServiceListWithCursors tests RequestService List with cursor pagination.
func TestRequestServiceListWithCursors(t *testing.T) {
	nextCursor := "cursor-abc"
	nextCursorID := "req-50"
	listResp := ListRequestsResponse{
		Requests: []RequestStatus{
			{ID: "req-1", Status: "pending"},
		},
		Total:        1,
		NextCursor:   &nextCursor,
		NextCursorID: &nextCursorID,
		HasMore:      false,
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, listResp))
	defer srv.Close()

	svc := &RequestService{transport: tr}
	resp, err := svc.List(context.Background(), &ListRequestsFilter{
		Status:        "pending",
		SignerAddress: "0xabc",
		ChainID:       "1",
		Limit:         10,
		Cursor:        &nextCursor,
		CursorID:      &nextCursorID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Requests) != 1 {
		t.Fatalf("len requests = %d", len(resp.Requests))
	}
}

// TestDecodeHexOrBase64 tests the decodeHexOrBase64 helper directly.
func TestDecodeHexOrBase64(t *testing.T) {
	// Test 0x-prefixed hex
	b, err := decodeHexOrBase64("0xdeadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 4 {
		t.Fatalf("len = %d", len(b))
	}

	// Test plain hex
	b, err = decodeHexOrBase64("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 4 {
		t.Fatalf("len = %d", len(b))
	}

	// Test base64 (string that is NOT also valid hex)
	b, err = decodeHexOrBase64("////") // 3 bytes of 0xFF
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 3 {
		t.Fatalf("len = %d", len(b))
	}

	// Test invalid
	_, err = decodeHexOrBase64("!!!")
	if err == nil {
		t.Fatal("expected error")
	}

	// Test isHex pure hex chars
	b, err = decodeHexOrBase64("ff")
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 1 {
		t.Fatalf("len = %d", len(b))
	}
}

// TestIsHex tests the isHex helper.
func TestIsHex(t *testing.T) {
	if !isHex("deadbeef") {
		t.Fatal("expected hex")
	}
	if !isHex("ABCDEF") {
		t.Fatal("expected hex uppercase")
	}
	if isHex("xyz") {
		t.Fatal("not hex")
	}
	if isHex("") {
		t.Fatal("empty is not hex")
	}
	if isHex("a") {
		t.Fatal("odd length is not hex")
	}
}

// TestRuleConfigJSON tests RuleConfig marshaling/unmarshaling.
func TestRuleConfigJSON(t *testing.T) {
	raw := json.RawMessage(`{"max_value":"1000"}`)
	cfg := RuleConfig(raw)

	marshaled, err := cfg.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if len(marshaled) == 0 {
		t.Fatal("expected non-empty")
	}

	var unmarshaled RuleConfig
	if err := unmarshaled.UnmarshalJSON(marshaled); err != nil {
		t.Fatal(err)
	}
	if string(unmarshaled) != string(raw) {
		t.Fatalf("got %s, want %s", string(unmarshaled), string(raw))
	}
}

// TestSignerServiceListWithFilters tests the SignerService.List with comprehensive filters.
func TestSignerServiceListWithFilters(t *testing.T) {
	listResp := ListSignersResponse{
		Signers: []Signer{
			{Address: "0xabc", Type: "keystore", Enabled: true},
		},
		Total:   1,
		HasMore: false,
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, listResp))
	defer srv.Close()

	svc := &SignerService{transport: tr}
	resp, err := svc.List(context.Background(), &ListSignersFilter{
		Type:             "keystore",
		Tag:              "test-tag",
		Limit:            10,
		Offset:           0,
		ExcludeHDDerived: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Signers) != 1 {
		t.Fatalf("len signers = %d", len(resp.Signers))
	}
}

// TestRemoteSigner_PersonalSign tests RemoteSigner's PersonalSign.
func TestRemoteSigner_PersonalSign(t *testing.T) {
	expectedSig := make([]byte, 65)
	srv, tr := testServer(t, jsonHandler(http.StatusOK, SignResponse{
		RequestID: "req-personal",
		Status:    StatusCompleted,
		Signature: "0x" + hex.EncodeToString(expectedSig),
	}))
	defer srv.Close()

	signer := &RemoteSigner{
		sign:    &SignService{transport: tr},
		address: common.HexToAddress("0x1234"),
		chainID: "1",
	}
	sig, err := signer.PersonalSign("hello world")
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 65 {
		t.Fatalf("len sig = %d", len(sig))
	}
}

// TestRemoteSigner_PersonalSignWithContext tests RemoteSigner's PersonalSignWithContext.
func TestRemoteSigner_PersonalSignWithContext(t *testing.T) {
	expectedSig := make([]byte, 65)
	srv, tr := testServer(t, jsonHandler(http.StatusOK, SignResponse{
		RequestID: "req-personal-ctx",
		Status:    StatusCompleted,
		Signature: "0x" + hex.EncodeToString(expectedSig),
	}))
	defer srv.Close()

	signer := &RemoteSigner{
		sign:    &SignService{transport: tr},
		address: common.HexToAddress("0x1234"),
		chainID: "1",
	}
	sig, err := signer.PersonalSignWithContext(context.Background(), "hello world")
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 65 {
		t.Fatalf("len sig = %d", len(sig))
	}
}

// TestRemoteSigner_SignTypedData tests RemoteSigner's SignTypedData.
func TestRemoteSigner_SignTypedData(t *testing.T) {
	expectedSig := make([]byte, 65)
	srv, tr := testServer(t, jsonHandler(http.StatusOK, SignResponse{
		RequestID: "req-typed",
		Status:    StatusCompleted,
		Signature: "0x" + hex.EncodeToString(expectedSig),
	}))
	defer srv.Close()

	signer := &RemoteSigner{
		sign:    &SignService{transport: tr},
		address: common.HexToAddress("0x1234"),
		chainID: "1",
	}

	typedData := eip712.TypedData{
		Types: eip712.Types{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
			},
			"Person": {
				{Name: "name", Type: "string"},
			},
		},
		PrimaryType: "Person",
		Domain: eip712.TypedDataDomain{
			Name: "test",
		},
		Message: map[string]interface{}{
			"name": "Alice",
		},
	}

	sig, err := signer.SignTypedData(typedData)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 65 {
		t.Fatalf("len sig = %d", len(sig))
	}
}

// TestRemoteSigner_SignTypedDataWithContext tests RemoteSigner's SignTypedDataWithContext.
func TestRemoteSigner_SignTypedDataWithContext(t *testing.T) {
	expectedSig := make([]byte, 65)
	srv, tr := testServer(t, jsonHandler(http.StatusOK, SignResponse{
		RequestID: "req-typed-ctx",
		Status:    StatusCompleted,
		Signature: "0x" + hex.EncodeToString(expectedSig),
	}))
	defer srv.Close()

	signer := &RemoteSigner{
		sign:    &SignService{transport: tr},
		address: common.HexToAddress("0x1234"),
		chainID: "1",
	}

	typedData := eip712.TypedData{
		Types: eip712.Types{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
			},
		},
		PrimaryType: "EIP712Domain",
		Domain: eip712.TypedDataDomain{
			Name:    "test",
			Version: "1",
		},
		Message: map[string]interface{}{
			"name": "test",
		},
	}

	sig, err := signer.SignTypedDataWithContext(context.Background(), typedData)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 65 {
		t.Fatalf("len sig = %d", len(sig))
	}
}

// TestRemoteSigner_SignTransactionLegacy tests RemoteSigner's SignTransactionWithChainID with a legacy tx.
func TestRemoteSigner_SignTransactionLegacy(t *testing.T) {
	// RLP-encoded unsigned legacy tx
	srv, tr := testServer(t, jsonHandler(http.StatusOK, SignResponse{
		RequestID:  "req-tx-legacy",
		Status:     StatusCompleted,
		SignedData: "0xe801843b9aca00825208940000000000000000000000000000000000005678648568656c6c6f808080",
	}))
	defer srv.Close()

	signer := &RemoteSigner{
		sign:    &SignService{transport: tr},
		address: common.HexToAddress("0x1234"),
		chainID: "1",
	}

	to := common.HexToAddress("0x5678")
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    1,
		To:       &to,
		Value:    big.NewInt(100),
		Gas:      21000,
		GasPrice: big.NewInt(1e9),
		Data:     []byte("hello"),
	})

	_, err := signer.SignTransactionWithChainID(tx, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
}

// TestRemoteSigner_SignTransactionEIP1559 tests RemoteSigner with an EIP-1559 tx.
func TestRemoteSigner_SignTransactionEIP1559(t *testing.T) {
	// RLP-encoded unsigned EIP-1559 tx
	srv, tr := testServer(t, jsonHandler(http.StatusOK, SignResponse{
		RequestID:  "req-tx-1559",
		Status:     StatusCompleted,
		SignedData: "0x02ef8002843b9aca00847735940082520894000000000000000000000000000000000000567881c88464617461c0808080",
	}))
	defer srv.Close()

	signer := &RemoteSigner{
		sign:    &SignService{transport: tr},
		address: common.HexToAddress("0x1234"),
		chainID: "1",
	}

	to := common.HexToAddress("0x5678")
	tx := types.NewTx(&types.DynamicFeeTx{
		Nonce:     2,
		To:        &to,
		Value:     big.NewInt(200),
		Gas:       21000,
		GasTipCap: big.NewInt(1e9),
		GasFeeCap: big.NewInt(2e9),
		Data:      []byte("data"),
	})

	_, err := signer.SignTransactionWithChainID(tx, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
}

// TestRemoteSigner_SignTransactionNoSignedData tests error handling when SignedData is empty.
func TestRemoteSigner_SignTransactionNoSignedData(t *testing.T) {
	// This still needs a valid RLP body so that the marshal/unmarshal doesn't fail
	srv, tr := testServer(t, jsonHandler(http.StatusOK, SignResponse{
		RequestID:  "req-tx-empty",
		Status:     StatusCompleted,
		SignedData: "",
	}))
	defer srv.Close()

	signer := &RemoteSigner{
		sign:    &SignService{transport: tr},
		address: common.HexToAddress("0x1234"),
		chainID: "1",
	}

	to := common.HexToAddress("0x5678")
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    1,
		To:       &to,
		Value:    big.NewInt(100),
		Gas:      21000,
		GasPrice: big.NewInt(1e9),
	})

	_, err := signer.SignTransactionWithChainID(tx, big.NewInt(1))
	if err == nil {
		t.Fatal("expected error for empty signed data")
	}
}

// TestRemoteSigner_SignTransactionWithContext tests the context variant of transaction signing.
func TestRemoteSigner_SignTransactionWithContext(t *testing.T) {
	srv, tr := testServer(t, jsonHandler(http.StatusOK, SignResponse{
		RequestID:  "req-tx-ctx",
		Status:     StatusCompleted,
		SignedData: "0xe801843b9aca00825208940000000000000000000000000000000000005678648568656c6c6f808080",
	}))
	defer srv.Close()

	signer := &RemoteSigner{
		sign:    &SignService{transport: tr},
		address: common.HexToAddress("0x1234"),
		chainID: "1",
	}

	to := common.HexToAddress("0x5678")
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    1,
		To:       &to,
		Value:    big.NewInt(0),
		Gas:      21000,
		GasPrice: big.NewInt(1e9),
	})

	_, err := signer.SignTransactionWithChainIDAndContext(context.Background(), tx, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
}

// TestRemoteSigner_ConvertToClientTypedData tests the internal helper.
func TestRemoteSigner_ConvertToClientTypedData(t *testing.T) {
	td := eip712.TypedData{
		Types: eip712.Types{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
			},
			"Person": {
				{Name: "name", Type: "string"},
				{Name: "wallet", Type: "address"},
			},
		},
		PrimaryType: "Person",
		Domain: eip712.TypedDataDomain{
			Name:              "test",
			Version:           "1",
			ChainId:           "1",
			VerifyingContract: "0xabc",
			Salt:              "0xsalt",
		},
		Message: map[string]interface{}{
			"name":   "Alice",
			"wallet": "0x1234",
		},
	}

	converted := convertToClientTypedData(td)
	if converted == nil {
		t.Fatal("expected non-nil result")
	}
	if converted.PrimaryType != "Person" {
		t.Fatalf("PrimaryType = %s", converted.PrimaryType)
	}
	if converted.Domain.Name != "test" {
		t.Fatalf("Domain.Name = %s", converted.Domain.Name)
	}
	if len(converted.Types) != 2 {
		t.Fatalf("len types = %d", len(converted.Types))
	}
}

// TestRemoteSigner_SignTransactionNoTo tests SignTransaction when To is nil (contract creation).
func TestRemoteSigner_SignTransactionNoTo(t *testing.T) {
	srv, tr := testServer(t, jsonHandler(http.StatusOK, SignResponse{
		RequestID:  "req-tx-create",
		Status:     StatusCompleted,
		SignedData: "0xd880843b9aca0082cf088080893630383036302e2e2e808080",
	}))
	defer srv.Close()

	signer := &RemoteSigner{
		sign:    &SignService{transport: tr},
		address: common.HexToAddress("0x1234"),
		chainID: "1",
	}

	// Contract creation tx has no To address
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		Value:    big.NewInt(0),
		Gas:      53000,
		GasPrice: big.NewInt(1e9),
		Data:     []byte("608060..."),
	})

	_, err := signer.SignTransactionWithChainID(tx, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
}
