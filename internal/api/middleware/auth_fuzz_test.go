package middleware

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/auth"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// mockAPIKeyRepo implements storage.APIKeyRepository for fuzz tests.
type mockAPIKeyRepo struct {
	keys map[string]*types.APIKey
}

func (m *mockAPIKeyRepo) Create(_ context.Context, key *types.APIKey) error {
	m.keys[key.ID] = key
	return nil
}

func (m *mockAPIKeyRepo) Get(_ context.Context, id string) (*types.APIKey, error) {
	key, ok := m.keys[id]
	if !ok {
		return nil, types.ErrNotFound
	}
	return key, nil
}

func (m *mockAPIKeyRepo) Update(_ context.Context, key *types.APIKey) error {
	m.keys[key.ID] = key
	return nil
}

func (m *mockAPIKeyRepo) Delete(_ context.Context, id string) error {
	delete(m.keys, id)
	return nil
}

func (m *mockAPIKeyRepo) List(_ context.Context, _ storage.APIKeyFilter) ([]*types.APIKey, error) {
	var result []*types.APIKey
	for _, key := range m.keys {
		result = append(result, key)
	}
	return result, nil
}

func (m *mockAPIKeyRepo) UpdateLastUsed(_ context.Context, _ string) error {
	return nil
}

func (m *mockAPIKeyRepo) Count(_ context.Context, _ storage.APIKeyFilter) (int, error) {
	return len(m.keys), nil
}

func (m *mockAPIKeyRepo) DeleteBySourceExcluding(_ context.Context, _ string, _ []string) (int64, error) {
	return 0, nil
}

func (m *mockAPIKeyRepo) BackfillSource(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

// mockNonceStore implements storage.NonceStore for fuzz tests.
type mockNonceStore struct {
	seen map[string]bool
}

func (m *mockNonceStore) CheckAndStore(_ context.Context, apiKeyID, nonce string, _ time.Duration) (bool, error) {
	key := apiKeyID + ":" + nonce
	if m.seen[key] {
		return false, nil
	}
	m.seen[key] = true
	return true, nil
}

// setupFuzzVerifier creates a verifier with a known Ed25519 key pair.
func setupFuzzVerifier(t testing.TB) (*auth.Verifier, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	repo := &mockAPIKeyRepo{keys: map[string]*types.APIKey{
		"test-key": {
			ID:           "test-key",
			Name:         "Fuzz Test Key",
			PublicKeyHex: hex.EncodeToString(pub),
			Enabled:      true,
			Admin:        true,
		},
	}}

	nonceStore := &mockNonceStore{seen: make(map[string]bool)}

	verifier, err := auth.NewVerifierWithNonceStore(repo, nonceStore, auth.Config{
		MaxRequestAge: 60 * time.Second,
		NonceRequired: true,
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	return verifier, pub, priv
}

// FuzzAuthMiddleware_Headers fuzzes the auth middleware with random header values.
// Goal: ensure no panics or unexpected crashes from malformed headers.
func FuzzAuthMiddleware_Headers(f *testing.F) {
	// Seed corpus with representative inputs
	f.Add("", "", "", "")                              // all empty
	f.Add("test-key", "not-a-number", "badsig", "")   // invalid timestamp
	f.Add("test-key", "1700000000000", "badsig", "")   // invalid signature
	f.Add("unknown-key", "1700000000000", "dGVzdA==", "abc") // unknown key
	f.Add("test-key", "99999999999999999", "dGVzdA==", "nonce123") // future timestamp
	f.Add("test-key", "0", "dGVzdA==", "nonce123")     // epoch timestamp
	f.Add("test-key", "-1", "dGVzdA==", "nonce123")    // negative timestamp
	f.Add("test-key", "1700000000000", "", "nonce123")  // empty signature
	f.Add("test-key", "1700000000000", "!!!invalid-base64!!!", "nonce123") // bad base64

	verifier, _, _ := setupFuzzVerifier(f)
	logger := newTestLogger()
	middleware := AuthMiddleware(verifier, logger, nil)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	f.Fuzz(func(t *testing.T, apiKeyID, timestamp, signature, nonce string) {
		body := []byte(`{"chain_id":"1","signer_address":"0xabc","sign_type":"transaction","payload":{}}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/sign", bytes.NewReader(body))

		if apiKeyID != "" {
			req.Header.Set("X-API-Key-ID", apiKeyID)
		}
		if timestamp != "" {
			req.Header.Set("X-Timestamp", timestamp)
		}
		if signature != "" {
			req.Header.Set("X-Signature", signature)
		}
		if nonce != "" {
			req.Header.Set("X-Nonce", nonce)
		}

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		// Must return a valid HTTP status code, never panic
		if rr.Code < 100 || rr.Code > 599 {
			t.Errorf("invalid HTTP status code: %d", rr.Code)
		}

		// Unauthenticated requests must never return 200
		if apiKeyID == "" || timestamp == "" || signature == "" {
			if rr.Code == http.StatusOK {
				t.Errorf("missing auth headers returned 200 OK (apiKeyID=%q, timestamp=%q, sig=%q)",
					apiKeyID, timestamp, signature)
			}
		}
	})
}

// FuzzAuthMiddleware_Body fuzzes the request body while using valid auth headers.
// Goal: ensure body parsing doesn't cause panics when body is arbitrary bytes.
func FuzzAuthMiddleware_Body(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"chain_id":"1"}`))
	f.Add([]byte("null"))
	f.Add(make([]byte, 1024*1024)) // 1MB of zeros

	verifier, _, priv := setupFuzzVerifier(f)
	logger := newTestLogger()
	middleware := AuthMiddleware(verifier, logger, nil)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	var nonceCounter atomic.Uint64

	f.Fuzz(func(t *testing.T, body []byte) {
		ts := time.Now().UnixMilli()
		nonce := fmt.Sprintf("fuzz-body-%d", nonceCounter.Add(1))
		method := http.MethodPost
		path := "/api/v1/evm/sign"

		// Create valid signature for this body
		bodyHash := sha256.Sum256(body)
		message := fmt.Sprintf("%d|%s|%s|%s|%x", ts, nonce, method, path, bodyHash)
		sig := ed25519.Sign(priv, []byte(message))
		sigB64 := base64.StdEncoding.EncodeToString(sig)

		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("X-API-Key-ID", "test-key")
		req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
		req.Header.Set("X-Signature", sigB64)
		req.Header.Set("X-Nonce", nonce)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code < 100 || rr.Code > 599 {
			t.Errorf("invalid HTTP status code: %d", rr.Code)
		}
	})
}

// FuzzParseTimestamp fuzzes the timestamp parsing function.
func FuzzParseTimestamp(f *testing.F) {
	f.Add("")
	f.Add("0")
	f.Add("-1")
	f.Add("1700000000000")
	f.Add("99999999999999999999999")
	f.Add("abc")
	f.Add("1.5")
	f.Add(" 123 ")

	f.Fuzz(func(t *testing.T, input string) {
		// Must never panic
		_, _ = auth.ParseTimestamp(input)
	})
}
