package client_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

func TestNewClient(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	tests := []struct {
		name    string
		cfg     client.Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with private key",
			cfg: client.Config{
				BaseURL:    "http://localhost:8080",
				APIKeyID:   "test-key",
				PrivateKey: privateKey,
			},
			wantErr: false,
		},
		{
			name: "valid config with private key hex (seed)",
			cfg: client.Config{
				BaseURL:       "http://localhost:8080",
				APIKeyID:      "test-key",
				PrivateKeyHex: hex.EncodeToString(privateKey.Seed()),
			},
			wantErr: false,
		},
		{
			name: "valid config with private key hex (full)",
			cfg: client.Config{
				BaseURL:       "http://localhost:8080",
				APIKeyID:      "test-key",
				PrivateKeyHex: hex.EncodeToString(privateKey),
			},
			wantErr: false,
		},
		{
			name: "missing base URL",
			cfg: client.Config{
				APIKeyID:   "test-key",
				PrivateKey: privateKey,
			},
			wantErr: true,
			errMsg:  "BaseURL is required",
		},
		{
			name: "missing API key ID",
			cfg: client.Config{
				BaseURL:    "http://localhost:8080",
				PrivateKey: privateKey,
			},
			wantErr: true,
			errMsg:  "APIKeyID is required",
		},
		{
			name: "missing private key",
			cfg: client.Config{
				BaseURL:  "http://localhost:8080",
				APIKeyID: "test-key",
			},
			wantErr: true,
			errMsg:  "either PrivateKey, PrivateKeyHex, or PrivateKeyBase64 is required",
		},
		{
			name: "invalid private key hex",
			cfg: client.Config{
				BaseURL:       "http://localhost:8080",
				APIKeyID:      "test-key",
				PrivateKeyHex: "invalid-hex",
			},
			wantErr: true,
			errMsg:  "invalid PrivateKeyHex",
		},
		{
			name: "invalid private key length",
			cfg: client.Config{
				BaseURL:       "http://localhost:8080",
				APIKeyID:      "test-key",
				PrivateKeyHex: "0102030405",
			},
			wantErr: true,
			errMsg:  "invalid private key length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := client.NewClient(tt.cfg)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, c)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, c)
			}
		})
	}
}

func TestClient_Health(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/health", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(client.HealthResponse{
			Status:  "healthy",
			Version: "1.0.0",
		})
	}))
	defer server.Close()

	_, privateKey, _ := ed25519.GenerateKey(nil)
	c, err := client.NewClient(client.Config{
		BaseURL:    server.URL,
		APIKeyID:   "test-key",
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	health, err := c.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "healthy", health.Status)
	assert.Equal(t, "1.0.0", health.Version)
}

func TestClient_Sign_AutoApproved(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/evm/sign", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		apiKeyID := r.Header.Get("X-API-Key-ID")
		assert.Equal(t, "test-key", apiKeyID)

		timestamp := r.Header.Get("X-Timestamp")
		assert.NotEmpty(t, timestamp)

		signature := r.Header.Get("X-Signature")
		assert.NotEmpty(t, signature)

		nonce := r.Header.Get("X-Nonce")
		assert.NotEmpty(t, nonce, "nonce should be present by default")

		var body []byte
		if r.Body != nil {
			body, _ = readAndRestoreBody(r)
		}
		bodyHash := sha256.Sum256(body)
		message := fmt.Sprintf("%s|%s|%s|%s|%x", timestamp, nonce, r.Method, r.URL.Path, bodyHash)
		sigBytes, _ := base64.StdEncoding.DecodeString(signature)
		assert.True(t, ed25519.Verify(publicKey, []byte(message), sigBytes))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(evm.SignResponse{
			RequestID:  "req_123",
			Status:     evm.StatusCompleted,
			Signature:  "0x" + hex.EncodeToString(make([]byte, 65)),
			SignedData: "",
		})
	}))
	defer server.Close()

	c, err := client.NewClient(client.Config{
		BaseURL:    server.URL,
		APIKeyID:   "test-key",
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	resp, err := c.EVM.Sign.Execute(context.Background(), &evm.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x1234567890123456789012345678901234567890",
		SignType:      evm.SignTypePersonal,
		Payload:       json.RawMessage(`{"message":"hello"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, "req_123", resp.RequestID)
	assert.Equal(t, evm.StatusCompleted, resp.Status)
	assert.NotEmpty(t, resp.Signature)
}

func TestClient_Sign_PendingApproval(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(nil)

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/v1/evm/sign" {
			json.NewEncoder(w).Encode(evm.SignResponse{
				RequestID: "req_456",
				Status:    evm.StatusAuthorizing,
				Message:   "pending manual approval",
			})
			return
		}

		if r.URL.Path == "/api/v1/evm/requests/req_456" {
			requestCount++
			if requestCount < 3 {
				json.NewEncoder(w).Encode(evm.RequestStatus{
					ID:     "req_456",
					Status: evm.StatusAuthorizing,
				})
			} else {
				json.NewEncoder(w).Encode(evm.RequestStatus{
					ID:        "req_456",
					Status:    evm.StatusCompleted,
					Signature: "0x" + hex.EncodeToString(make([]byte, 65)),
				})
			}
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	c, err := client.NewClient(client.Config{
		BaseURL:      server.URL,
		APIKeyID:     "test-key",
		PrivateKey:   privateKey,
		PollInterval: 100 * time.Millisecond,
		PollTimeout:  5 * time.Second,
	})
	require.NoError(t, err)

	resp, err := c.EVM.Sign.Execute(context.Background(), &evm.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x1234567890123456789012345678901234567890",
		SignType:      evm.SignTypePersonal,
		Payload:       json.RawMessage(`{"message":"hello"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, "req_456", resp.RequestID)
	assert.Equal(t, evm.StatusCompleted, resp.Status)
	assert.Equal(t, 3, requestCount)
}

func TestClient_Sign_Rejected(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(nil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(evm.SignResponse{
			RequestID: "req_789",
			Status:    evm.StatusRejected,
			Message:   "request rejected by admin",
		})
	}))
	defer server.Close()

	c, err := client.NewClient(client.Config{
		BaseURL:    server.URL,
		APIKeyID:   "test-key",
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	_, err = c.EVM.Sign.Execute(context.Background(), &evm.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x1234567890123456789012345678901234567890",
		SignType:      evm.SignTypePersonal,
		Payload:       json.RawMessage(`{"message":"hello"}`),
	})
	require.Error(t, err)

	var signErr *evm.SignError
	require.ErrorAs(t, err, &signErr)
	assert.Equal(t, evm.StatusRejected, signErr.Status)
	assert.Equal(t, "req_789", signErr.RequestID)
}

func TestClient_GetRequest(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(nil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/evm/requests/req_test", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(evm.RequestStatus{
			ID:            "req_test",
			ChainType:     "evm",
			ChainID:       "1",
			SignerAddress: "0x1234567890123456789012345678901234567890",
			SignType:      evm.SignTypePersonal,
			Status:        evm.StatusCompleted,
			Signature:     "0xabc123",
		})
	}))
	defer server.Close()

	c, err := client.NewClient(client.Config{
		BaseURL:    server.URL,
		APIKeyID:   "test-key",
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	status, err := c.EVM.Requests.Get(context.Background(), "req_test")
	require.NoError(t, err)
	assert.Equal(t, "req_test", status.ID)
	assert.Equal(t, evm.StatusCompleted, status.Status)
}

func TestAPIError(t *testing.T) {
	tests := []struct {
		name    string
		err     *client.APIError
		wantMsg string
	}{
		{
			name:    "with message",
			err:     &client.APIError{StatusCode: 401, Code: "unauthorized", Message: "invalid key"},
			wantMsg: "API error 401 (unauthorized): invalid key",
		},
		{
			name:    "without message",
			err:     &client.APIError{StatusCode: 500, Code: "internal_error"},
			wantMsg: "API error 500: internal_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantMsg, tt.err.Error())
		})
	}
}

func TestSignError_Is(t *testing.T) {
	tests := []struct {
		name   string
		err    *client.SignError
		target error
		want   bool
	}{
		{
			name:   "pending approval",
			err:    &client.SignError{Status: evm.StatusAuthorizing},
			target: client.ErrPendingApproval,
			want:   true,
		},
		{
			name:   "rejected",
			err:    &client.SignError{Status: evm.StatusRejected},
			target: client.ErrRejected,
			want:   true,
		},
		{
			name:   "mismatch",
			err:    &client.SignError{Status: evm.StatusCompleted},
			target: client.ErrPendingApproval,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Is(tt.target))
		})
	}
}

func readAndRestoreBody(r *http.Request) ([]byte, error) {
	body := make([]byte, r.ContentLength)
	r.Body.Read(body)
	return body, nil
}

func TestRemoteSigner_GetAddress(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(nil)

	c, err := client.NewClient(client.Config{
		BaseURL:    "http://localhost:8080",
		APIKeyID:   "test-key",
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	signer := evm.NewRemoteSigner(c.EVM.Sign, addr, "1")

	assert.Equal(t, addr, signer.GetAddress())
}

func TestRemoteSigner_PersonalSign(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(nil)

	expectedSig := make([]byte, 65)
	for i := range expectedSig {
		expectedSig[i] = byte(i)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/evm/sign", r.URL.Path)

		var req evm.SignRequest
		json.NewDecoder(r.Body).Decode(&req)

		assert.Equal(t, evm.SignTypePersonal, req.SignType)

		var payload evm.MessagePayload
		json.Unmarshal(req.Payload, &payload)
		assert.Equal(t, "Hello, World!", payload.Message)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(evm.SignResponse{
			RequestID: "req_sig",
			Status:    evm.StatusCompleted,
			Signature: "0x" + hex.EncodeToString(expectedSig),
		})
	}))
	defer server.Close()

	c, err := client.NewClient(client.Config{
		BaseURL:    server.URL,
		APIKeyID:   "test-key",
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	signer := evm.NewRemoteSigner(c.EVM.Sign, addr, "1")

	sig, err := signer.PersonalSign("Hello, World!")
	require.NoError(t, err)
	assert.Equal(t, expectedSig, sig)
}

func TestRemoteSigner_SignHash(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(nil)

	expectedSig := make([]byte, 65)
	testHash := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req evm.SignRequest
		json.NewDecoder(r.Body).Decode(&req)

		assert.Equal(t, evm.SignTypeHash, req.SignType)

		var payload evm.HashPayload
		json.Unmarshal(req.Payload, &payload)
		assert.Equal(t, testHash.Hex(), payload.Hash)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(evm.SignResponse{
			RequestID: "req_hash",
			Status:    evm.StatusCompleted,
			Signature: "0x" + hex.EncodeToString(expectedSig),
		})
	}))
	defer server.Close()

	c, err := client.NewClient(client.Config{
		BaseURL:    server.URL,
		APIKeyID:   "test-key",
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	signer := evm.NewRemoteSigner(c.EVM.Sign, common.HexToAddress("0x1234"), "1")

	sig, err := signer.SignHash(testHash)
	require.NoError(t, err)
	assert.Equal(t, expectedSig, sig)
}
