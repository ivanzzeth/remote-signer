package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// --- mocks ---

type mockAPIKeyRepo struct {
	getFn           func(ctx context.Context, id string) (*types.APIKey, error)
	updateLastUsed  func(ctx context.Context, id string) error
}

func (m *mockAPIKeyRepo) Create(_ context.Context, _ *types.APIKey) error { return nil }
func (m *mockAPIKeyRepo) Get(ctx context.Context, id string) (*types.APIKey, error) {
	return m.getFn(ctx, id)
}
func (m *mockAPIKeyRepo) Update(_ context.Context, _ *types.APIKey) error { return nil }
func (m *mockAPIKeyRepo) Delete(_ context.Context, _ string) error        { return nil }
func (m *mockAPIKeyRepo) List(_ context.Context, _ storage.APIKeyFilter) ([]*types.APIKey, error) {
	return nil, nil
}
func (m *mockAPIKeyRepo) Count(_ context.Context, _ storage.APIKeyFilter) (int, error) { return 0, nil }
func (m *mockAPIKeyRepo) UpdateLastUsed(ctx context.Context, id string) error {
	if m.updateLastUsed != nil {
		return m.updateLastUsed(ctx, id)
	}
	return nil
}
func (m *mockAPIKeyRepo) DeleteBySourceExcluding(_ context.Context, _ string, _ []string) (int64, error) {
	return 0, nil
}
func (m *mockAPIKeyRepo) BackfillSource(_ context.Context, _ string) (int64, error) { return 0, nil }

type mockNonceStore struct {
	checkAndStoreFn func(ctx context.Context, apiKeyID, nonce string, ttl time.Duration) (bool, error)
}

func (m *mockNonceStore) CheckAndStore(ctx context.Context, apiKeyID, nonce string, ttl time.Duration) (bool, error) {
	return m.checkAndStoreFn(ctx, apiKeyID, nonce, ttl)
}

// --- helpers ---

func generateKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func validAPIKey(pub ed25519.PublicKey) *types.APIKey {
	return &types.APIKey{
		ID:           "test-key-1",
		Name:         "test",
		PublicKeyHex: hex.EncodeToString(pub),
		Enabled:      true,
		Role:         types.RoleAgent,
	}
}

func signedMessage(priv ed25519.PrivateKey, ts int64, nonce, method, path string, body []byte) string {
	return SignRequestWithNonce(priv, ts, nonce, method, path, body)
}

// --- factory tests ---

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, 60*time.Second, cfg.MaxRequestAge)
	assert.True(t, cfg.NonceRequired)
}

func TestNewVerifier_NilRepo(t *testing.T) {
	_, err := NewVerifier(nil, DefaultConfig())
	assert.ErrorContains(t, err, "API key repository is required")
}

func TestNewVerifier_InvalidMaxAge(t *testing.T) {
	_, err := NewVerifier(&mockAPIKeyRepo{}, Config{MaxRequestAge: 0, NonceRequired: false})
	assert.ErrorContains(t, err, "max request age must be positive")
}

func TestNewVerifier_NonceRequiredWithoutStore(t *testing.T) {
	cfg := DefaultConfig()
	_, err := NewVerifier(&mockAPIKeyRepo{}, cfg)
	assert.ErrorContains(t, err, "NonceRequired is true but no nonce store provided")
}

func TestNewVerifier_Success(t *testing.T) {
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: false}
	v, err := NewVerifier(&mockAPIKeyRepo{}, cfg)
	require.NoError(t, err)
	assert.NotNil(t, v)
}

func TestNewVerifierWithNonceStore_NilRepo(t *testing.T) {
	_, err := NewVerifierWithNonceStore(nil, &mockNonceStore{}, DefaultConfig())
	assert.ErrorContains(t, err, "API key repository is required")
}

func TestNewVerifierWithNonceStore_InvalidMaxAge(t *testing.T) {
	_, err := NewVerifierWithNonceStore(&mockAPIKeyRepo{}, &mockNonceStore{}, Config{MaxRequestAge: 0, NonceRequired: false})
	assert.ErrorContains(t, err, "max request age must be positive")
}

func TestNewVerifierWithNonceStore_NilStore(t *testing.T) {
	_, err := NewVerifierWithNonceStore(&mockAPIKeyRepo{}, nil, Config{MaxRequestAge: 60 * time.Second, NonceRequired: false})
	assert.ErrorContains(t, err, "nonce store is required")
}

func TestNewVerifierWithNonceStore_Success(t *testing.T) {
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: true}
	v, err := NewVerifierWithNonceStore(&mockAPIKeyRepo{}, &mockNonceStore{}, cfg)
	require.NoError(t, err)
	assert.NotNil(t, v)
}

// --- verifyRequestInternal tests ---

func TestVerifyRequest_KeyNotFound(t *testing.T) {
	repo := &mockAPIKeyRepo{getFn: func(_ context.Context, id string) (*types.APIKey, error) {
		return nil, types.ErrNotFound
	}}
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: false}
	v, err := NewVerifier(repo, cfg)
	require.NoError(t, err)

	_, err = v.VerifyRequest(context.Background(), "unknown", 1, "sig", "GET", "/", nil)
	assert.ErrorContains(t, err, "not found")
	assert.ErrorIs(t, err, types.ErrUnauthorized)
}

func TestVerifyRequest_KeyDisabled(t *testing.T) {
	repo := &mockAPIKeyRepo{getFn: func(_ context.Context, id string) (*types.APIKey, error) {
		return &types.APIKey{ID: id, Enabled: false, PublicKeyHex: "abcd"}, nil
	}}
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: false}
	v, err := NewVerifier(repo, cfg)
	require.NoError(t, err)

	_, err = v.VerifyRequest(context.Background(), "disabled-key", 1, "sig", "GET", "/", nil)
	assert.ErrorContains(t, err, "disabled")
	assert.ErrorIs(t, err, types.ErrUnauthorized)
}

func TestVerifyRequest_KeyExpired(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	repo := &mockAPIKeyRepo{getFn: func(_ context.Context, id string) (*types.APIKey, error) {
		return &types.APIKey{ID: id, Enabled: true, PublicKeyHex: "abcd", ExpiresAt: &past}, nil
	}}
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: false}
	v, err := NewVerifier(repo, cfg)
	require.NoError(t, err)

	_, err = v.VerifyRequest(context.Background(), "expired-key", 1, "sig", "GET", "/", nil)
	assert.ErrorContains(t, err, "expired")
	assert.ErrorIs(t, err, types.ErrUnauthorized)
}

func TestVerifyRequest_FutureTimestamp(t *testing.T) {
	pub, _ := generateKeyPair(t)
	repo := &mockAPIKeyRepo{getFn: func(_ context.Context, id string) (*types.APIKey, error) {
		return validAPIKey(pub), nil
	}}
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: false}
	v, err := NewVerifier(repo, cfg)
	require.NoError(t, err)

	future := time.Now().Add(10 * time.Second).UnixMilli()
	_, err = v.VerifyRequest(context.Background(), "test-key-1", future, "sig", "GET", "/", nil)
	assert.ErrorContains(t, err, "future")
	assert.ErrorIs(t, err, types.ErrUnauthorized)
}

func TestVerifyRequest_TooOld(t *testing.T) {
	pub, _ := generateKeyPair(t)
	repo := &mockAPIKeyRepo{getFn: func(_ context.Context, id string) (*types.APIKey, error) {
		return validAPIKey(pub), nil
	}}
	cfg := Config{MaxRequestAge: 1 * time.Second, NonceRequired: false}
	v, err := NewVerifier(repo, cfg)
	require.NoError(t, err)

	old := time.Now().Add(-10 * time.Second).UnixMilli()
	_, err = v.VerifyRequest(context.Background(), "test-key-1", old, "sig", "GET", "/", nil)
	assert.ErrorContains(t, err, "too old")
	assert.ErrorIs(t, err, types.ErrUnauthorized)
}

func TestVerifyRequest_NonceRequiredButEmpty(t *testing.T) {
	pub, _ := generateKeyPair(t)
	repo := &mockAPIKeyRepo{getFn: func(_ context.Context, id string) (*types.APIKey, error) {
		return validAPIKey(pub), nil
	}}
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: true}
	v, err := NewVerifierWithNonceStore(repo, &mockNonceStore{}, cfg)
	require.NoError(t, err)

	_, err = v.VerifyRequest(context.Background(), "test-key-1", time.Now().UnixMilli(), "sig", "GET", "/", nil)
	assert.ErrorContains(t, err, "nonce header required")
	assert.ErrorIs(t, err, types.ErrUnauthorized)
}

func TestVerifyRequest_InvalidPublicKeyHex(t *testing.T) {
	repo := &mockAPIKeyRepo{getFn: func(_ context.Context, id string) (*types.APIKey, error) {
		return &types.APIKey{ID: id, Enabled: true, PublicKeyHex: "not-hex"}, nil
	}}
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: false}
	v, err := NewVerifier(repo, cfg)
	require.NoError(t, err)

	_, err = v.VerifyRequest(context.Background(), "bad-key", time.Now().UnixMilli(), "sig", "GET", "/", nil)
	assert.ErrorContains(t, err, "invalid public key hex")
}

func TestVerifyRequest_WrongPublicKeySize(t *testing.T) {
	repo := &mockAPIKeyRepo{getFn: func(_ context.Context, id string) (*types.APIKey, error) {
		return &types.APIKey{ID: id, Enabled: true, PublicKeyHex: "aabb"}, nil
	}}
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: false}
	v, err := NewVerifier(repo, cfg)
	require.NoError(t, err)

	_, err = v.VerifyRequest(context.Background(), "bad-key", time.Now().UnixMilli(), "sig", "GET", "/", nil)
	assert.ErrorContains(t, err, "invalid public key size")
}

func TestVerifyRequest_InvalidSignatureBase64(t *testing.T) {
	pub, _ := generateKeyPair(t)
	repo := &mockAPIKeyRepo{getFn: func(_ context.Context, id string) (*types.APIKey, error) {
		return validAPIKey(pub), nil
	}}
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: false}
	v, err := NewVerifier(repo, cfg)
	require.NoError(t, err)

	_, err = v.VerifyRequest(context.Background(), "test-key-1", time.Now().UnixMilli(), "!!!invalid-base64!!!", "GET", "/", nil)
	assert.ErrorContains(t, err, "invalid signature encoding")
}

func TestVerifyRequest_BadSignature(t *testing.T) {
	pub, _ := generateKeyPair(t)
	repo := &mockAPIKeyRepo{getFn: func(_ context.Context, id string) (*types.APIKey, error) {
		return validAPIKey(pub), nil
	}}
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: false}
	v, err := NewVerifier(repo, cfg)
	require.NoError(t, err)

	_, err = v.VerifyRequest(context.Background(), "test-key-1", time.Now().UnixMilli(), "AAAA", "GET", "/", nil)
	assert.ErrorContains(t, err, "signature verification failed")
}

func TestVerifyRequest_Success(t *testing.T) {
	pub, priv := generateKeyPair(t)
	ts := time.Now().UnixMilli()
	sig := SignRequest(priv, ts, "POST", "/api/sign", []byte(`{"data":"test"}`))

	repo := &mockAPIKeyRepo{getFn: func(_ context.Context, id string) (*types.APIKey, error) {
		return validAPIKey(pub), nil
	}}
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: false}
	v, err := NewVerifier(repo, cfg)
	require.NoError(t, err)

	key, err := v.VerifyRequest(context.Background(), "test-key-1", ts, sig, "POST", "/api/sign", []byte(`{"data":"test"}`))
	require.NoError(t, err)
	assert.Equal(t, "test-key-1", key.ID)
}

func TestVerifyRequest_Success_UpdatesLastUsed(t *testing.T) {
	pub, priv := generateKeyPair(t)
	ts := time.Now().UnixMilli()
	sig := SignRequest(priv, ts, "GET", "/health", nil)

	done := make(chan string, 1)
	repo := &mockAPIKeyRepo{
		getFn: func(_ context.Context, id string) (*types.APIKey, error) {
			return validAPIKey(pub), nil
		},
		updateLastUsed: func(_ context.Context, id string) error {
			done <- id
			return nil
		},
	}
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: false}
	v, err := NewVerifier(repo, cfg)
	require.NoError(t, err)

	_, err = v.VerifyRequest(context.Background(), "test-key-1", ts, sig, "GET", "/health", nil)
	require.NoError(t, err)

	select {
	case got := <-done:
		assert.Equal(t, "test-key-1", got)
	case <-time.After(2 * time.Second):
		t.Fatal("UpdateLastUsed was not called")
	}
}

func TestVerifyRequestWithNonce_Success(t *testing.T) {
	pub, priv := generateKeyPair(t)
	ts := time.Now().UnixMilli()
	nonce := "abc123"
	sig := signedMessage(priv, ts, nonce, "GET", "/v1/sign", []byte(`{}`))

	repo := &mockAPIKeyRepo{getFn: func(_ context.Context, id string) (*types.APIKey, error) {
		return validAPIKey(pub), nil
	}}
	ns := &mockNonceStore{checkAndStoreFn: func(_ context.Context, _, _ string, _ time.Duration) (bool, error) {
		return true, nil
	}}
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: true}
	v, err := NewVerifierWithNonceStore(repo, ns, cfg)
	require.NoError(t, err)

	key, err := v.VerifyRequestWithNonce(context.Background(), "test-key-1", ts, nonce, sig, "GET", "/v1/sign", []byte(`{}`))
	require.NoError(t, err)
	assert.Equal(t, "test-key-1", key.ID)
}

func TestVerifyRequestWithNonce_Replay(t *testing.T) {
	pub, priv := generateKeyPair(t)
	ts := time.Now().UnixMilli()
	nonce := "replay-nonce"
	sig := signedMessage(priv, ts, nonce, "DELETE", "/x", nil)

	repo := &mockAPIKeyRepo{getFn: func(_ context.Context, id string) (*types.APIKey, error) {
		return validAPIKey(pub), nil
	}}
	ns := &mockNonceStore{checkAndStoreFn: func(_ context.Context, _, _ string, _ time.Duration) (bool, error) {
		return false, nil // nonce already used
	}}
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: true}
	v, err := NewVerifierWithNonceStore(repo, ns, cfg)
	require.NoError(t, err)

	_, err = v.VerifyRequestWithNonce(context.Background(), "test-key-1", ts, nonce, sig, "DELETE", "/x", nil)
	assert.ErrorContains(t, err, "already used")
	assert.ErrorIs(t, err, types.ErrUnauthorized)
}

func TestVerifyRequestWithNonce_NonceStoreError(t *testing.T) {
	pub, priv := generateKeyPair(t)
	ts := time.Now().UnixMilli()
	nonce := "error-nonce"
	sig := signedMessage(priv, ts, nonce, "POST", "/y", []byte(`{}`))

	repo := &mockAPIKeyRepo{getFn: func(_ context.Context, id string) (*types.APIKey, error) {
		return validAPIKey(pub), nil
	}}
	ns := &mockNonceStore{checkAndStoreFn: func(_ context.Context, _, _ string, _ time.Duration) (bool, error) {
		return false, errors.New("store unavailable")
	}}
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: true}
	v, err := NewVerifierWithNonceStore(repo, ns, cfg)
	require.NoError(t, err)

	_, err = v.VerifyRequestWithNonce(context.Background(), "test-key-1", ts, nonce, sig, "POST", "/y", []byte(`{}`))
	assert.ErrorContains(t, err, "failed to check nonce")
}

// --- ParseTimestamp ---

func TestParseTimestamp_Valid(t *testing.T) {
	ts, err := ParseTimestamp("1234567890")
	require.NoError(t, err)
	assert.Equal(t, int64(1234567890), ts)
}

func TestParseTimestamp_Invalid(t *testing.T) {
	_, err := ParseTimestamp("not-a-number")
	assert.ErrorContains(t, err, "invalid timestamp")
}

// --- SignRequest ---

func TestSignRequest(t *testing.T) {
	_, priv := generateKeyPair(t)
	sig := SignRequest(priv, 1000, "GET", "/test", []byte("body"))
	assert.NotEmpty(t, sig)
}

func TestSignRequestWithNonce(t *testing.T) {
	_, priv := generateKeyPair(t)
	sig := SignRequestWithNonce(priv, 2000, "n1", "POST", "/test", []byte("data"))
	assert.NotEmpty(t, sig)
}

func TestSignRoundTrip(t *testing.T) {
	pub, priv := generateKeyPair(t)
	ts := time.Now().UnixMilli()
	nonce := "roundtrip-nonce"
	body := []byte(`{"json":"rpc"}`)
	sig := SignRequestWithNonce(priv, ts, nonce, "PUT", "/v1/sign", body)

	repo := &mockAPIKeyRepo{getFn: func(_ context.Context, id string) (*types.APIKey, error) {
		return validAPIKey(pub), nil
	}}
	ns := &mockNonceStore{checkAndStoreFn: func(_ context.Context, _, _ string, _ time.Duration) (bool, error) {
		return true, nil
	}}
	cfg := Config{MaxRequestAge: 60 * time.Second, NonceRequired: true}
	v, err := NewVerifierWithNonceStore(repo, ns, cfg)
	require.NoError(t, err)

	key, err := v.VerifyRequestWithNonce(context.Background(), "test-key-1", ts, nonce, sig, "PUT", "/v1/sign", body)
	require.NoError(t, err)
	assert.Equal(t, "test-key-1", key.ID)
}
