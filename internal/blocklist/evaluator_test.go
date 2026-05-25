//go:build integration

package blocklist

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEvaluator(t *testing.T) {
	// Nil blocklist should error.
	_, err := NewEvaluator(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocklist is required")

	// Non-nil blocklist should succeed.
	bl := &DynamicBlocklist{}
	e, err := NewEvaluator(bl)
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.Equal(t, bl, e.blocklist)
}

func TestEvaluator_Type(t *testing.T) {
	e, err := NewEvaluator(&DynamicBlocklist{})
	require.NoError(t, err)
	assert.Equal(t, types.RuleTypeEVMDynamicBlocklist, e.Type())
}

func TestEvaluator_AppliesToSignType(t *testing.T) {
	e, err := NewEvaluator(&DynamicBlocklist{})
	require.NoError(t, err)
	// Should always return true regardless of sign type.
	assert.True(t, e.AppliesToSignType(nil, "transaction"))
	assert.True(t, e.AppliesToSignType(nil, "typed_data"))
	assert.True(t, e.AppliesToSignType(nil, "personal_sign"))
}

func TestEvaluator_Evaluate_FailClosed(t *testing.T) {
	// Fail-closed mode with no cached addresses + failed sync = IsFailClosed true.
	cfg := Config{
		Enabled:  true,
		FailMode: "close",
		Sources: []SourceConfig{
			{Name: "broken", Type: "url_text", URL: "http://localhost:1/nonexistent"},
		},
	}
	bl, err := NewDynamicBlocklist(cfg, testLogger())
	require.NoError(t, err)
	err = bl.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	defer bl.Stop()

	waitForSync(t, bl, 10*time.Second)
	assert.True(t, bl.IsFailClosed())

	e, err := NewEvaluator(bl)
	require.NoError(t, err)

	blocked, reason, err := e.Evaluate(context.Background(), &types.Rule{
		Mode: types.RuleModeBlocklist,
	}, &types.SignRequest{}, nil)
	assert.NoError(t, err)
	assert.True(t, blocked)
	assert.Contains(t, reason, "fail-close")
}

func TestEvaluator_Evaluate_TransactionRecipientNotBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b\n"))
	}))
	defer srv.Close()

	cfg := Config{
		Enabled:  true,
		FailMode: "open",
		Sources:  []SourceConfig{{Name: "test", Type: "url_text", URL: srv.URL}},
	}
	bl, err := NewDynamicBlocklist(cfg, testLogger())
	require.NoError(t, err)
	err = bl.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	defer bl.Stop()
	time.Sleep(500 * time.Millisecond)

	e, err := NewEvaluator(bl)
	require.NoError(t, err)

	recipient := "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
	blocked, reason, err := e.Evaluate(context.Background(), &types.Rule{
		Mode: types.RuleModeBlocklist,
		Config: mustMarshal(t, EvaluatorConfig{
			CheckRecipient: true,
		}),
	}, &types.SignRequest{}, &types.ParsedPayload{
		Recipient: &recipient,
	})
	assert.NoError(t, err)
	assert.False(t, blocked)
	assert.Empty(t, reason)
}

func TestEvaluator_Evaluate_TransactionRecipientBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b\n"))
	}))
	defer srv.Close()

	cfg := Config{
		Enabled:  true,
		FailMode: "open",
		Sources:  []SourceConfig{{Name: "test", Type: "url_text", URL: srv.URL}},
	}
	bl, err := NewDynamicBlocklist(cfg, testLogger())
	require.NoError(t, err)
	err = bl.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	defer bl.Stop()
	time.Sleep(500 * time.Millisecond)

	e, err := NewEvaluator(bl)
	require.NoError(t, err)

	recipient := "0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b"
	blocked, reason, err := e.Evaluate(context.Background(), &types.Rule{
		Mode: types.RuleModeBlocklist,
		Config: mustMarshal(t, EvaluatorConfig{
			CheckRecipient: true,
		}),
	}, &types.SignRequest{}, &types.ParsedPayload{
		Recipient: &recipient,
	})
	assert.NoError(t, err)
	assert.True(t, blocked)
	assert.Contains(t, reason, "dynamic blocklist")
}

func TestEvaluator_Evaluate_TypedDataVerifyingContractBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b\n"))
	}))
	defer srv.Close()

	cfg := Config{
		Enabled:  true,
		FailMode: "open",
		Sources:  []SourceConfig{{Name: "test", Type: "url_text", URL: srv.URL}},
	}
	bl, err := NewDynamicBlocklist(cfg, testLogger())
	require.NoError(t, err)
	err = bl.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	defer bl.Stop()
	time.Sleep(500 * time.Millisecond)

	e, err := NewEvaluator(bl)
	require.NoError(t, err)

	payload := json.RawMessage(`{"typed_data":{"domain":{"verifyingContract":"0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b"}}}`)
	blocked, reason, err := e.Evaluate(context.Background(), &types.Rule{
		Mode: types.RuleModeBlocklist,
		Config: mustMarshal(t, EvaluatorConfig{
			CheckVerifyingContract: true,
		}),
	}, &types.SignRequest{
		SignType: "typed_data",
		Payload:  payload,
	}, nil)
	assert.NoError(t, err)
	assert.True(t, blocked)
	assert.Contains(t, reason, "dynamic blocklist")
}

func TestEvaluator_Evaluate_SignTypeNotTransaction(t *testing.T) {
	e, err := NewEvaluator(&DynamicBlocklist{})
	require.NoError(t, err)

	// SignType != "transaction" and nil parsed payload → Evaluate should return false, not error.
	blocked, reason, err := e.Evaluate(context.Background(), &types.Rule{
		Mode: types.RuleModeBlocklist,
		Config: mustMarshal(t, EvaluatorConfig{
			CheckRecipient: true,
		}),
	}, &types.SignRequest{}, nil)
	assert.NoError(t, err)
	assert.False(t, blocked)
	assert.Empty(t, reason)
}

func TestEvaluator_Evaluate_InvalidConfig(t *testing.T) {
	e, err := NewEvaluator(&DynamicBlocklist{})
	require.NoError(t, err)

	// Invalid config JSON.
	blocked, reason, err := e.Evaluate(context.Background(), &types.Rule{
		Mode:   types.RuleModeBlocklist,
		Config: []byte("{invalid json}"),
	}, &types.SignRequest{}, nil)
	assert.Error(t, err)
	assert.False(t, blocked)
	assert.Empty(t, reason)
}

func TestExtractVerifyingContract_Valid(t *testing.T) {
	payload := []byte(`{"typed_data":{"domain":{"verifyingContract":"0xabcd"}}}`)
	vc := extractVerifyingContract(payload)
	assert.Equal(t, "0xabcd", vc)
}

func TestExtractVerifyingContract_InvalidJSON(t *testing.T) {
	vc := extractVerifyingContract([]byte("{not-json}"))
	assert.Empty(t, vc)
}

func TestExtractVerifyingContract_MissingFields(t *testing.T) {
	vc := extractVerifyingContract([]byte(`{"typed_data":{}}`))
	assert.Empty(t, vc)
}

func TestExtractVerifyingContract_NilDomain(t *testing.T) {
	vc := extractVerifyingContract([]byte(`{"typed_data":{"domain":null}}`))
	assert.Empty(t, vc)
}

func TestExtractVerifyingContract_EmptyPayload(t *testing.T) {
	vc := extractVerifyingContract([]byte{})
	assert.Empty(t, vc)
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return data
}
