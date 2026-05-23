package middleware

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/auth"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestVerifier creates a verifier with a known Ed25519 key pair for testing.
func setupTestVerifier(t testing.TB) (*auth.Verifier, ed25519.PrivateKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	repo := &mockAPIKeyRepo{keys: map[string]*types.APIKey{
		"test-key": {
			ID:           "test-key",
			Name:         "Test Key",
			PublicKeyHex: hex.EncodeToString(pub),
			Enabled:      true,
			Role:         types.RoleAdmin,
		},
	}}

	nonceStore := &mockNonceStore{seen: make(map[string]bool)}

	verifier, err := auth.NewVerifierWithNonceStore(repo, nonceStore, auth.Config{
		MaxRequestAge: 60 * time.Second,
		NonceRequired: false,
	})
	require.NoError(t, err)

	return verifier, priv
}

func TestAuthMiddleware_InvalidSignatureFormat(t *testing.T) {
	verifier, _ := setupTestVerifier(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	mw := AuthMiddleware(verifier, logger, nil)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name      string
		signature string
		wantCode  int
	}{
		{"not valid base64", "!!!invalid-base64!!!", http.StatusUnauthorized},
		{"empty signature", "", http.StatusUnauthorized},
		{"binary garbage", "\x00\x01\x02\x03", http.StatusUnauthorized},
		{"too short signature", base64.StdEncoding.EncodeToString([]byte("short")), http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(`{"chain_id":"1"}`)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/sign", bytes.NewReader(body))
			req.Header.Set("X-API-Key-ID", "test-key")
			req.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().UnixMilli()))
			req.Header.Set("X-Signature", tt.signature)
			req.Header.Set("X-Nonce", "test-nonce")
			req.ContentLength = int64(len(body))

			rr := httptest.NewRecorder()
			mw(next).ServeHTTP(rr, req)
			assert.Equal(t, tt.wantCode, rr.Code, tt.name)
			assert.False(t, called, "next handler should not be called for %s", tt.name)
		})
	}
}

func TestAuthMiddleware_MissingHeaders(t *testing.T) {
	verifier, _ := setupTestVerifier(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	mw := AuthMiddleware(verifier, logger, nil)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	})

	tests := []struct {
		name    string
		headers map[string]string
	}{
		{"no headers at all", nil},
		{"only API key", map[string]string{"X-API-Key-ID": "test-key"}},
		{"missing signature", map[string]string{
			"X-API-Key-ID": "test-key",
			"X-Timestamp":  "1700000000000",
		}},
		{"missing timestamp", map[string]string{
			"X-API-Key-ID": "test-key",
			"X-Signature":  "abc",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/sign", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			rr := httptest.NewRecorder()
			mw(next).ServeHTTP(rr, req)
			assert.Equal(t, http.StatusUnauthorized, rr.Code)
		})
	}
}

func TestAuthMiddleware_HeaderTooLong(t *testing.T) {
	verifier, _ := setupTestVerifier(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	mw := AuthMiddleware(verifier, logger, nil)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	})

	// API key ID longer than 128 chars.
	longKey := make([]byte, 129)
	for i := range longKey {
		longKey[i] = 'a'
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/sign", nil)
	req.Header.Set("X-API-Key-ID", string(longKey))
	req.Header.Set("X-Timestamp", "1700000000000")
	req.Header.Set("X-Signature", "abc")

	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
