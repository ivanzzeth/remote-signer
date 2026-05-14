//go:build e2e

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// =============================================================================
// TLS / mTLS E2E Tests
// =============================================================================
//
// These tests programmatically generate self-signed certificates, start a
// TLS-enabled server, and verify that:
//  1. Client with proper mTLS certs can connect successfully
//  2. Client without client cert is rejected (mTLS)
//  3. Client without TLS config fails to connect to HTTPS server

// tlsCerts holds the generated certificate paths for a test
type tlsCerts struct {
	dir        string
	caCert     string
	caKey      string
	serverCert string
	serverKey  string
	clientCert string
	clientKey  string
}

// generateTestCerts generates a CA, server, and client certificate for testing.
// All certs are written to a temp directory.
func generateTestCerts(t *testing.T) *tlsCerts {
	t.Helper()

	dir := t.TempDir()
	certs := &tlsCerts{
		dir:        dir,
		caCert:     filepath.Join(dir, "ca.crt"),
		caKey:      filepath.Join(dir, "ca.key"),
		serverCert: filepath.Join(dir, "server.crt"),
		serverKey:  filepath.Join(dir, "server.key"),
		clientCert: filepath.Join(dir, "client.crt"),
		clientKey:  filepath.Join(dir, "client.key"),
	}

	// ---- CA ----
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"RemoteSigner Test CA"},
			CommonName:   "RemoteSigner Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)

	caCertParsed, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	writePEM(t, certs.caCert, "CERTIFICATE", caCertDER)
	writeECKey(t, certs.caKey, caPrivKey)

	// ---- Server Cert ----
	serverPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"RemoteSigner Test Server"},
			CommonName:   "localhost",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCertParsed, &serverPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)

	writePEM(t, certs.serverCert, "CERTIFICATE", serverCertDER)
	writeECKey(t, certs.serverKey, serverPrivKey)

	// ---- Client Cert ----
	clientPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"RemoteSigner Test Client"},
			CommonName:   "test-client",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCertParsed, &clientPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)

	writePEM(t, certs.clientCert, "CERTIFICATE", clientCertDER)
	writeECKey(t, certs.clientKey, clientPrivKey)

	return certs
}

// writePEM writes a PEM-encoded block to a file
func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	err = pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
	require.NoError(t, err)
}

// writeECKey writes an ECDSA private key to a PEM file
func writeECKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	writePEM(t, path, "EC PRIVATE KEY", der)
}

// =============================================================================
// TLS E2E Test Functions
// =============================================================================

func TestTLS_ServerStartsWithTLS(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Skipping: TLS tests require internal server mode")
	}

	certs := generateTestCerts(t)

	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Generate API keys
	adminPubKey, adminPrivKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	adminKeyID := "tls-test-admin"
	adminKeyHex := hex.EncodeToString(adminPrivKey)

	os.Setenv("E2E_TEST_SIGNER_KEY", testSignerPrivateKey)
	defer os.Unsetenv("E2E_TEST_SIGNER_KEY")

	// Create and start TLS test server with mTLS enabled
	ts, err := NewTestServer(TestServerConfig{
		Port:            port,
		SignerPrivateKey: testSignerPrivateKey,
		SignerAddress:    testSignerAddress,
		APIKeyID:        adminKeyID,
		APIKeyPublicKey: adminPubKey,
	})
	require.NoError(t, err)
	ts.tlsCerts = certs // store certs so waitForTLSReady can use client cert

	err = ts.StartWithTLS(certs.serverCert, certs.serverKey, certs.caCert, true)
	require.NoError(t, err)
	defer ts.Stop()

	tlsBaseURL := fmt.Sprintf("https://127.0.0.1:%d", port)

	// Test 1: Client with proper mTLS certs can connect
	t.Run("mTLS client succeeds", func(t *testing.T) {
		c, err := client.NewClient(client.Config{
			BaseURL:       tlsBaseURL,
			APIKeyID:      adminKeyID,
			PrivateKeyHex: adminKeyHex,
			TLSCAFile:     certs.caCert,
			TLSCertFile:   certs.clientCert,
			TLSKeyFile:    certs.clientKey,
		})
		require.NoError(t, err)

		health, err := c.Health(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "ok", health.Status)
	})

	// Test 2: Client without client cert is rejected (mTLS)
	t.Run("client without cert rejected by mTLS", func(t *testing.T) {
		c, err := client.NewClient(client.Config{
			BaseURL:       tlsBaseURL,
			APIKeyID:      adminKeyID,
			PrivateKeyHex: adminKeyHex,
			TLSCAFile:     certs.caCert,
			// No client cert/key — mTLS should reject
		})
		require.NoError(t, err)

		_, err = c.Health(context.Background())
		require.Error(t, err, "should fail without client cert when mTLS is enabled")
	})

	// Test 3: Client without TLS config fails (no CA cert to verify server)
	t.Run("plain HTTP client fails on HTTPS", func(t *testing.T) {
		c, err := client.NewClient(client.Config{
			BaseURL:       tlsBaseURL,
			APIKeyID:      adminKeyID,
			PrivateKeyHex: adminKeyHex,
			// No TLS config at all — should fail cert verification
		})
		require.NoError(t, err)

		_, err = c.Health(context.Background())
		require.Error(t, err, "should fail without CA cert for self-signed server")
	})

	// Test 4: Client with TLSSkipVerify but no client cert — still rejected by mTLS
	t.Run("skip verify without client cert still rejected by mTLS", func(t *testing.T) {
		c, err := client.NewClient(client.Config{
			BaseURL:       tlsBaseURL,
			APIKeyID:      adminKeyID,
			PrivateKeyHex: adminKeyHex,
			TLSSkipVerify: true,
			// No client cert — mTLS should still reject
		})
		require.NoError(t, err)

		_, err = c.Health(context.Background())
		require.Error(t, err, "mTLS should reject even with skip verify when no client cert")
	})
}

func TestTLS_ServerWithTLSOnlyNoMTLS(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Skipping: TLS tests require internal server mode")
	}

	certs := generateTestCerts(t)

	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Generate API keys
	adminPubKey, adminPrivKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	adminKeyID := "tls-nomtls-admin"
	adminKeyHex := hex.EncodeToString(adminPrivKey)

	os.Setenv("E2E_TEST_SIGNER_KEY", testSignerPrivateKey)
	defer os.Unsetenv("E2E_TEST_SIGNER_KEY")

	// Create TLS server WITHOUT mTLS (client_auth: false)
	ts, err := NewTestServer(TestServerConfig{
		Port:            port,
		SignerPrivateKey: testSignerPrivateKey,
		SignerAddress:    testSignerAddress,
		APIKeyID:        adminKeyID,
		APIKeyPublicKey: adminPubKey,
	})
	require.NoError(t, err)

	// Start with TLS but without mTLS
	err = ts.StartWithTLS(certs.serverCert, certs.serverKey, "", false)
	require.NoError(t, err)
	defer ts.Stop()

	tlsBaseURL := fmt.Sprintf("https://127.0.0.1:%d", port)

	// Test: Client with CA cert but no client cert should succeed (no mTLS)
	t.Run("TLS client without client cert succeeds when mTLS disabled", func(t *testing.T) {
		c, err := client.NewClient(client.Config{
			BaseURL:       tlsBaseURL,
			APIKeyID:      adminKeyID,
			PrivateKeyHex: adminKeyHex,
			TLSCAFile:     certs.caCert,
			// No client cert needed when mTLS is disabled
		})
		require.NoError(t, err)

		health, err := c.Health(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "ok", health.Status)
	})

	// Test: Client with skip verify should also succeed
	t.Run("TLS client with skip verify succeeds", func(t *testing.T) {
		c, err := client.NewClient(client.Config{
			BaseURL:       tlsBaseURL,
			APIKeyID:      adminKeyID,
			PrivateKeyHex: adminKeyHex,
			TLSSkipVerify: true,
		})
		require.NoError(t, err)

		health, err := c.Health(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "ok", health.Status)
	})
}

func TestTLS_SigningOverMTLS(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Skipping: TLS tests require internal server mode")
	}

	certs := generateTestCerts(t)

	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Generate API keys
	adminPubKey, adminPrivKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	adminKeyID := "tls-sign-admin"
	adminKeyHex := hex.EncodeToString(adminPrivKey)

	os.Setenv("E2E_TEST_SIGNER_KEY", testSignerPrivateKey)
	defer os.Unsetenv("E2E_TEST_SIGNER_KEY")

	ts, err := NewTestServer(TestServerConfig{
		Port:            port,
		SignerPrivateKey: testSignerPrivateKey,
		SignerAddress:    testSignerAddress,
		APIKeyID:        adminKeyID,
		APIKeyPublicKey: adminPubKey,
	})
	require.NoError(t, err)
	ts.tlsCerts = certs // store certs so waitForTLSReady can use client cert

	err = ts.StartWithTLS(certs.serverCert, certs.serverKey, certs.caCert, true)
	require.NoError(t, err)
	defer ts.Stop()

	tlsBaseURL := fmt.Sprintf("https://127.0.0.1:%d", port)

	// Create mTLS client
	c, err := client.NewClient(client.Config{
		BaseURL:       tlsBaseURL,
		APIKeyID:      adminKeyID,
		PrivateKeyHex: adminKeyHex,
		TLSCAFile:     certs.caCert,
		TLSCertFile:   certs.clientCert,
		TLSKeyFile:    certs.clientKey,
		PollInterval:  100 * time.Millisecond,
		PollTimeout:   5 * time.Second,
	})
	require.NoError(t, err)

	// Test: Sign a message over mTLS
	ctx := context.Background()
	resp, err := c.EVM.Sign.Execute(ctx, &evm.SignRequest{
		ChainID:       testChainID,
		SignerAddress: testSignerAddress,
		SignType:      evm.SignTypePersonal,
		Payload:       []byte(`{"message":"Hello over mTLS!"}`),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Signature, "signature should not be empty over mTLS")
	assert.Equal(t, "completed", string(resp.Status))
}

// =============================================================================
// TestServer TLS extension
// =============================================================================
//
// StartWithTLS extends TestServer to support starting with TLS/mTLS.
// This is added here rather than modifying test_server.go to keep TLS
// test code isolated.

func (ts *TestServer) StartWithTLS(certFile, keyFile, caFile string, enableMTLS bool) error {
	// Set environment variable for signer private key
	os.Setenv("E2E_TEST_SIGNER_KEY", ts.config.SignerPrivateKey)

	// Use the same initialization as Start(), but with TLS config injected
	log := newTestLogger()

	// Initialize isolated in-memory SQLite database (unique per test)
	db, err := initTestDB()
	if err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}
	ts.db = db

	// Initialize repositories
	requestRepo, ruleRepo, apiKeyRepo, auditRepo, err := initTestRepositories(db)
	if err != nil {
		return err
	}

	// Create API key
	if err := ts.createAPIKey(apiKeyRepo); err != nil {
		return fmt.Errorf("failed to create API key: %w", err)
	}

	// Create whitelist rule
	if err := ts.createWhitelistRule(ruleRepo); err != nil {
		return fmt.Errorf("failed to create whitelist rule: %w", err)
	}

	// Create sign type restriction rule
	if err := ts.createSignTypeRestrictionRule(ruleRepo); err != nil {
		return fmt.Errorf("failed to create sign type restriction rule: %w", err)
	}

	// Initialize all services and create server with TLS
	server, err := initTestServices(ts, requestRepo, ruleRepo, apiKeyRepo, auditRepo, log,
		certFile, keyFile, caFile, enableMTLS, db)
	if err != nil {
		return err
	}
	ts.server = server

	// Update baseURL for TLS
	ts.baseURL = fmt.Sprintf("https://127.0.0.1:%d", ts.config.Port)

	// Start server in background
	ctx, cancel := context.WithCancel(context.Background())
	ts.cancelFunc = cancel

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Wait for server to be ready (using TLS-aware health check)
	// When mTLS is enabled the health-check client must present a client cert,
	// otherwise every probe is rejected and the server appears "not ready".
	if err := ts.waitForTLSReady(ctx, enableMTLS); err != nil {
		cancel()
		return fmt.Errorf("TLS server failed to start: %w", err)
	}

	// Check if server errored during startup
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			cancel()
			return fmt.Errorf("server error: %w", err)
		}
	default:
	}

	return nil
}

// waitForTLSReady waits for the TLS server to be ready.
// When mTLS is enabled the health-check HTTP client must present a valid client
// certificate, otherwise the TLS handshake is rejected and the server will never
// appear "ready".
func (ts *TestServer) waitForTLSReady(ctx context.Context, mTLSEnabled bool) error {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // Test health check only
	}

	// When mTLS is enabled, load a client cert so the health-check passes
	// the TLS handshake. The cert files are in the same temp dir as the
	// server certs (convention: sibling files client.crt / client.key).
	if mTLSEnabled && ts.tlsCerts != nil {
		cert, err := tls.LoadX509KeyPair(ts.tlsCerts.clientCert, ts.tlsCerts.clientKey)
		if err != nil {
			return fmt.Errorf("failed to load client cert for health check: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	httpClient := &http.Client{
		Timeout: 1 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	healthURL := ts.baseURL + "/health"

	for i := 0; i < 50; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		resp, err := httpClient.Get(healthURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}

		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("TLS server did not become ready in time")
}
