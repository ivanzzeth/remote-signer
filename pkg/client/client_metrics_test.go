package client_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

func TestClient_Health_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/health", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "service_unavailable",
			"message": "not ready",
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

	_, err = c.Health(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service_unavailable")
}

func TestClient_Health_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	_, privateKey, _ := ed25519.GenerateKey(nil)
	c, err := client.NewClient(client.Config{
		BaseURL:    server.URL,
		APIKeyID:   "test-key",
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	_, err = c.Health(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode response")
}

func TestClient_Metrics_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/metrics", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("# HELP http_requests_total Total requests\n# TYPE http_requests_total counter\nhttp_requests_total 42\n"))
	}))
	defer server.Close()

	_, privateKey, _ := ed25519.GenerateKey(nil)
	c, err := client.NewClient(client.Config{
		BaseURL:    server.URL,
		APIKeyID:   "test-key",
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	metrics, err := c.Metrics(context.Background())
	require.NoError(t, err)
	assert.Contains(t, metrics, "http_requests_total 42")
}

func TestClient_Metrics_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer server.Close()

	_, privateKey, _ := ed25519.GenerateKey(nil)
	c, err := client.NewClient(client.Config{
		BaseURL:    server.URL,
		APIKeyID:   "test-key",
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	_, err = c.Metrics(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metrics request failed")
	assert.Contains(t, err.Error(), "500")
}

func TestClient_Metrics_EmptyBodyOnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, privateKey, _ := ed25519.GenerateKey(nil)
	c, err := client.NewClient(client.Config{
		BaseURL:    server.URL,
		APIKeyID:   "test-key",
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	_, err = c.Metrics(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500 Internal Server Error")
}

func TestClient_Metrics_NetworkError(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(nil)
	c, err := client.NewClient(client.Config{
		BaseURL:    "http://127.0.0.1:1",
		APIKeyID:   "test-key",
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	_, err = c.Metrics(context.Background())
	require.Error(t, err)
}

func TestClient_ConfigWithTLS(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(nil)

	c, err := client.NewClient(client.Config{
		BaseURL:       "http://localhost:8080",
		APIKeyID:      "test-key",
		PrivateKey:    privateKey,
		TLSSkipVerify: true,
	})
	require.NoError(t, err)
	assert.NotNil(t, c)
}

func TestClient_CustomHTTPClient(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(nil)
	customClient := &http.Client{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(client.HealthResponse{
			Status:  "healthy",
			Version: "1.0.0",
		})
	}))
	defer server.Close()

	c, err := client.NewClient(client.Config{
		BaseURL:    server.URL,
		APIKeyID:   "test-key",
		PrivateKey: privateKey,
		HTTPClient: customClient,
	})
	require.NoError(t, err)

	health, err := c.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "healthy", health.Status)
}

func TestClient_Sign_InvalidPayloadJSON(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(nil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "invalid_payload",
			"message": "invalid payload format",
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
		SignerAddress: "0x1234",
		SignType:      evm.SignTypePersonal,
		Payload:       []byte(`{"message":"test"}`),
	})
	require.Error(t, err)

	var apiErr *client.APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, 400, apiErr.StatusCode)
	assert.Equal(t, "invalid_payload", apiErr.Code)
}

func TestClient_Sign_NetworkError(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(nil)
	c, err := client.NewClient(client.Config{
		BaseURL:    "http://127.0.0.1:1",
		APIKeyID:   "test-key",
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	_, err = c.EVM.Sign.Execute(context.Background(), &evm.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x1234",
		SignType:      evm.SignTypePersonal,
		Payload:       []byte(`{"message":"test"}`),
	})
	require.Error(t, err)
}

func TestClient_Sign_ContextCancelled(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(nil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(evm.SignResponse{
			RequestID: "req_cancel",
			Status:    evm.StatusAuthorizing,
			Message:   "pending approval",
		})
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

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = c.EVM.Sign.Execute(ctx, &evm.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x1234",
		SignType:      evm.SignTypePersonal,
		Payload:       []byte(`{"message":"test"}`),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestClient_APIError_StatusCode(t *testing.T) {
	err := &client.APIError{StatusCode: 429, Code: "rate_limited", Message: "too many requests"}
	assert.True(t, err.IsStatusCode(429))
	assert.False(t, err.IsStatusCode(200))
}

func TestClient_APIError_Code(t *testing.T) {
	err := &client.APIError{StatusCode: 403, Code: "forbidden", Message: "access denied"}
	assert.True(t, err.IsCode("forbidden"))
	assert.False(t, err.IsCode("unauthorized"))
}

func TestClient_SentinelErrors(t *testing.T) {
	assert.ErrorIs(t, client.ErrPendingApproval, evm.ErrPendingApproval)
	assert.ErrorIs(t, client.ErrRejected, evm.ErrRejected)
	assert.ErrorIs(t, client.ErrNotFound, evm.ErrNotFound)
	assert.ErrorIs(t, client.ErrTimeout, evm.ErrTimeout)
	assert.ErrorIs(t, client.ErrUnauthorized, evm.ErrUnauthorized)
}
