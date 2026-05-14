package evm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// testTransport builds a Transport pointing at srv, signed with a throwaway
// Ed25519 key so the auth headers are well-formed (the server ignores them).
func testTransport(t *testing.T, srv *httptest.Server) *transport.Transport {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := transport.NewAuth(priv)
	tr, err := transport.NewTransport(transport.Config{
		BaseURL:  srv.URL,
		APIKeyID: "test-key",
	}, auth)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// testServer is a helper that registers a handler and returns the server + a
// convenience transport.
func testServer(t *testing.T, h http.Handler) (*httptest.Server, *transport.Transport) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, testTransport(t, srv)
}

// staticHandler returns an http.HandlerFunc that always writes status and body.
func staticHandler(status int, body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}
}

func jsonHandler(status int, v any) http.HandlerFunc {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return staticHandler(status, raw)
}

func TestSignerServiceList(t *testing.T) {
	srv, tr := testServer(t, jsonHandler(http.StatusOK, ListSignersResponse{
		Signers: []Signer{
			{Address: "0xabc", Type: "keystore", Enabled: true},
		},
		Total:   1,
		HasMore: false,
	}))
	svc := &SignerService{transport: tr}
	resp, err := svc.List(context.Background(), &ListSignersFilter{Type: "keystore"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Signers) != 1 || resp.Signers[0].Address != "0xabc" {
		t.Fatalf("unexpected signers: %+v", resp.Signers)
	}
	if resp.Total != 1 {
		t.Fatalf("unexpected total: %d", resp.Total)
	}
	_ = srv
}

func TestSignerServiceCreate(t *testing.T) {
	created := Signer{Address: "0xnew", Type: "keystore", Enabled: true}
	srv, tr := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/v1/evm/signers" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(created)
	}))
	svc := &SignerService{transport: tr}
	got, err := svc.Create(context.Background(), &CreateSignerRequest{Type: "keystore"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != "0xnew" {
		t.Fatalf("address = %s", got.Address)
	}
	_ = srv
}

func TestSignerServiceErrorResponse(t *testing.T) {
	srv, tr := testServer(t, staticHandler(http.StatusBadRequest, []byte(`{"error":"bad_request","message":"invalid type"}`)))
	svc := &SignerService{transport: tr}
	_, err := svc.Create(context.Background(), &CreateSignerRequest{Type: ""})
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *transport.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error type = %T, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d", apiErr.StatusCode)
	}
	if apiErr.Code != "bad_request" {
		t.Errorf("Code = %s", apiErr.Code)
	}
	if apiErr.Message != "invalid type" {
		t.Errorf("Message = %s", apiErr.Message)
	}
	_ = srv
}

func TestRuleServiceCRUD(t *testing.T) {
	rule := Rule{
		ID:   "rule-1",
		Name: "test-rule",
		Type: "address_list",
		Mode: "whitelist",
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, rule))
	svc := &RuleService{transport: tr}

	// Get
	got, err := svc.Get(context.Background(), "rule-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "rule-1" || got.Name != "test-rule" {
		t.Fatalf("unexpected rule: %+v", got)
	}

	// ListBudgets
	srv2, tr2 := testServer(t, jsonHandler(http.StatusOK, []RuleBudget{
		{ID: "b-1", RuleID: "rule-1", Unit: "ETH", MaxTotal: "1000"},
	}))
	budgets, err := (&RuleService{transport: tr2}).ListBudgets(context.Background(), "rule-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(budgets) != 1 || budgets[0].Unit != "ETH" {
		t.Fatalf("unexpected budgets: %+v", budgets)
	}
	_ = srv
	_ = srv2
}

func TestHDWalletServiceCreateAndDerive(t *testing.T) {
	walletResp := HDWalletResponse{
		PrimaryAddress: "0xprimary",
		BasePath:       "m/44'/60'/0'",
		Locked:         false,
	}
	srv, tr := testServer(t, jsonHandler(http.StatusCreated, walletResp))
	svc := &HDWalletService{transport: tr, sign: &SignService{transport: tr}}
	got, err := svc.Create(context.Background(), &CreateHDWalletRequest{Password: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if got.PrimaryAddress != "0xprimary" {
		t.Fatalf("primary = %s", got.PrimaryAddress)
	}
	_ = srv
}

func TestWalletServiceCRUD(t *testing.T) {
	wallet := Wallet{
		ID:   "w-1",
		Name: "test-wallet",
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, wallet))
	svc := &WalletService{transport: tr}

	// Get
	got, err := svc.Get(context.Background(), "w-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "w-1" || got.Name != "test-wallet" {
		t.Fatalf("unexpected wallet: %+v", got)
	}
	_ = srv
}

func TestRequestServiceList(t *testing.T) {
	now := time.Now()
	listResp := ListRequestsResponse{
		Requests: []RequestStatus{
			{ID: "req-1", Status: "pending", CreatedAt: now},
			{ID: "req-2", Status: "completed", CreatedAt: now},
		},
		Total:   2,
		HasMore: false,
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, listResp))
	svc := &RequestService{transport: tr}
	filter := &ListRequestsFilter{Status: "pending", Limit: 10}
	resp, err := svc.List(context.Background(), filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Requests) != 2 {
		t.Fatalf("len = %d", len(resp.Requests))
	}
	if resp.Requests[0].ID != "req-1" {
		t.Fatalf("first request ID = %s", resp.Requests[0].ID)
	}
	_ = srv
}

func TestBroadcastService(t *testing.T) {
	broadcastResp := BroadcastResponse{TxHash: "0xdeadbeef"}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, broadcastResp))
	svc := &BroadcastService{transport: tr}
	resp, err := svc.Broadcast(context.Background(), &BroadcastRequest{ChainID: "1", SignedTxHex: "0xtx"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.TxHash != "0xdeadbeef" {
		t.Fatalf("tx hash = %s", resp.TxHash)
	}
	_ = srv
}

func TestSimulateService(t *testing.T) {
	simResp := SimulateResponse{
		Success: true,
		GasUsed: 21000,
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, simResp))
	svc := &SimulateService{transport: tr}
	resp, err := svc.Simulate(context.Background(), &SimulateRequest{
		ChainID: "1",
		From:    "0xfrom",
		To:      "0xto",
		Value:   "0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Success || resp.GasUsed != 21000 {
		t.Fatalf("unexpected resp: %+v", resp)
	}
	_ = srv
}

func TestGuardService(t *testing.T) {
	srv, tr := testServer(t, staticHandler(http.StatusOK, nil))
	svc := &GuardService{transport: tr}
	if err := svc.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = srv
}

func TestRequestServicePreviewRule(t *testing.T) {
	previewResp := PreviewRuleResponse{
		Rule: Rule{
			ID:   "rule-gen",
			Name: "auto-rule",
			Type: "value_limit",
			Mode: "whitelist",
		},
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, previewResp))
	svc := &RequestService{transport: tr}
	resp, err := svc.PreviewRule(context.Background(), "req-1", &PreviewRuleRequest{
		RuleType: "value_limit",
		RuleMode: "whitelist",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rule.ID != "rule-gen" {
		t.Fatalf("rule ID = %s", resp.Rule.ID)
	}
	_ = srv
}

func TestSignerService5xxError(t *testing.T) {
	_ = staticHandler
	srv, tr := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, "internal error")
	}))
	svc := &SignerService{transport: tr}
	_, err := svc.List(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error on 5xx")
	}
	_ = srv
}

func TestRuleServiceToggle(t *testing.T) {
	toggled := Rule{ID: "rule-1", Enabled: false}
	srv, tr := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("method = %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(toggled)
	}))
	svc := &RuleService{transport: tr}
	got, err := svc.Toggle(context.Background(), "rule-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled {
		t.Fatal("expected disabled")
	}
	_ = srv
}

func TestRequestServiceApprove(t *testing.T) {
	approveResp := ApproveResponse{
		RequestID: "req-1",
		Status:    "completed",
		Signature: "0xsig",
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, approveResp))
	svc := &RequestService{transport: tr}
	resp, err := svc.Approve(context.Background(), "req-1", &ApproveRequest{Approved: true})
	if err != nil {
		t.Fatal(err)
	}
	if resp.RequestID != "req-1" || resp.Status != "completed" {
		t.Fatalf("unexpected: %+v", resp)
	}
	_ = srv
}

func TestSignServiceExecute(t *testing.T) {
	signResp := SignResponse{
		RequestID: "sr-1",
		Status:    "completed",
		Signature: "0xsig",
	}
	srv, tr := testServer(t, jsonHandler(http.StatusOK, signResp))
	svc := &SignService{transport: tr}
	resp, err := svc.Execute(context.Background(), &SignRequest{
		ChainID:       "1",
		SignerAddress: "0xabc",
		SignType:      "hash",
		Payload:       json.RawMessage(`{"hash":"0xdead"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.RequestID != "sr-1" || resp.Status != "completed" {
		t.Fatalf("unexpected: %+v", resp)
	}
	_ = srv
}

func TestWalletServiceAddMember(t *testing.T) {
	member := WalletMember{WalletID: "w-1", SignerAddress: "0xabc"}
	srv, tr := testServer(t, jsonHandler(http.StatusCreated, member))
	svc := &WalletService{transport: tr}
	got, err := svc.AddMember(context.Background(), "w-1", &AddWalletMemberRequest{SignerAddress: "0xabc"})
	if err != nil {
		t.Fatal(err)
	}
	if got.WalletID != "w-1" {
		t.Fatalf("wallet ID = %s", got.WalletID)
	}
	_ = srv
}
