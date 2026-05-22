package admin

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ivanzzeth/ethsig/keystore"
	"github.com/spf13/cobra"
)

// `api-key bootstrap` is the CLI counterpart to the web-UI first-run flow.
//
// On a soft-started daemon (no env var, empty api_keys table), this
// subcommand prompts for a new keystore password on stdin, posts it to
// the daemon's POST /api/v1/bootstrap/admin endpoint, and reports the
// keystore paths the daemon wrote.
//
// Auth-wise: the endpoint is unauthenticated by design (there's no admin
// key to authenticate with yet), so this subcommand does NOT use the
// global --api-key-id / --api-key-keystore flags. It only needs --url.
//
// This is the ONE place a TTY password prompt still happens in the
// project — the daemon's own startup no longer reads from stdin. That
// keeps the "interactive password" surface area narrow and well-isolated
// from the daemon's lifecycle.
var apiKeyBootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Complete first-run admin keystore setup against a running daemon",
	Long: `Bootstrap the admin API key against a daemon that started without
REMOTE_SIGNER_KEYSTORE_PASSWORD set.

The daemon comes up in a soft-started state — listening on HTTP but with
an empty api_keys table — and accepts a single unauthenticated POST on
/api/v1/bootstrap/admin to finish setup. This command:

  1. Connects to the daemon at --url and checks GET /bootstrap/status.
     If status reports needs_bootstrap=false, exits without prompting.

  2. Prompts you on stdin for a new admin keystore password (twice, for
     confirmation). The password protects the encrypted Ed25519 keystore
     written to <daemon-home>/apikeys/admin.keystore.json — remember it.
     There's no recovery if you lose it.

  3. POSTs the password to /api/v1/bootstrap/admin. The daemon creates
     the keystore, inserts the api_keys row, and responds with the
     resulting paths.

  4. Prints the keystore path and public-key hex so you can verify the
     CLI matches what the daemon wrote.

Use this instead of restarting with REMOTE_SIGNER_KEYSTORE_PASSWORD when
the daemon is running under systemd / docker / launchd and bouncing it
would interrupt other work, or when you'd rather not put the password in
an environment-variable trail.`,
	RunE:                       runAPIKeyBootstrap,
	DisableAutoGenTag:          true,
	SuggestionsMinimumDistance: 2,
}

func runAPIKeyBootstrap(cmd *cobra.Command, _ []string) error {
	// Resolve daemon URL from the persistent --url flag the parent
	// command registers. flagURL is the same variable referenced by all
	// the auth-bearing CLI subcommands.
	if flagURL == "" {
		return fmt.Errorf("--url is required (or set REMOTE_SIGNER_URL)")
	}

	httpClient, err := newPlainHTTPClient(cmd)
	if err != nil {
		return err
	}

	statusURL := strings.TrimRight(flagURL, "/") + "/api/v1/bootstrap/status"
	adminURL := strings.TrimRight(flagURL, "/") + "/api/v1/bootstrap/admin"

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Phase 1: confirm bootstrap is still needed. Saves the operator a
	// pointless password prompt when the daemon has already been
	// configured via another path (env var, web UI, prior CLI run).
	needsBootstrap, err := fetchBootstrapStatus(ctx, httpClient, statusURL)
	if err != nil {
		return fmt.Errorf("query bootstrap status: %w", err)
	}
	if !needsBootstrap {
		return fmt.Errorf("daemon at %s already has an admin API key; bootstrap window has closed", flagURL)
	}

	// Phase 2: read the new password from the TTY. ReadPasswordWithConfirm
	// echoes nothing, requires a matching re-entry, and zeroises the
	// confirmation copy on its own.
	if !keystore.IsTerminal() {
		return fmt.Errorf(
			"stdin is not a terminal; cannot prompt for password securely.\n" +
				"Either run this command interactively, or restart the daemon with " +
				"REMOTE_SIGNER_KEYSTORE_PASSWORD set in its environment.",
		)
	}
	password, err := keystore.ReadPasswordWithConfirm(ctx, "Enter NEW admin keystore password")
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	defer keystore.SecureZeroize(password)

	// Phase 3: send the password to the daemon. The payload is just one
	// field, but we build it with the JSON encoder to handle any
	// escaping pitfalls (passwords containing quotes, backslashes, etc.)
	// rather than fmt.Sprintf'ing the body.
	body, err := json.Marshal(struct {
		Password string `json:"password"`
	}{Password: string(password)})
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	// Zero the marshalled buffer once the request fires — bytes.Buffer
	// holds the only other copy outside the http stack.
	defer func() {
		for i := range body {
			body[i] = 0
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, adminURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("call %s: %w", adminURL, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusGone {
		return errors.New("daemon reports admin already configured (HTTP 410). Another bootstrap path must have won the race")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bootstrap failed: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Status       string `json:"status"`
		KeystorePath string `json:"keystore_path"`
		PubKeyPath   string `json:"pub_key_path"`
		PubKeyHex    string `json:"public_key_hex"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("decode response: %w (body: %s)", err, string(respBody))
	}

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "[BOOTSTRAP] Admin API key created on the daemon.")
	fmt.Fprintln(cmd.OutOrStdout(), "  Keystore file:    "+result.KeystorePath)
	fmt.Fprintln(cmd.OutOrStdout(), "  Public key file:  "+result.PubKeyPath)
	fmt.Fprintln(cmd.OutOrStdout(), "  Public key (hex): "+result.PubKeyHex)
	fmt.Fprintln(cmd.OutOrStdout(), "  Role:             admin")
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "  These paths are relative to the daemon's home directory, not")
	fmt.Fprintln(cmd.OutOrStdout(), "  this machine. If you ran the CLI against a remote daemon, the")
	fmt.Fprintln(cmd.OutOrStdout(), "  files live on the remote host.")
	return nil
}

// fetchBootstrapStatus performs the pre-flight GET request. Pulled out
// of runAPIKeyBootstrap for testability — the integration test can mock
// the http.Client without driving the password prompt.
func fetchBootstrapStatus(ctx context.Context, client *http.Client, url string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return false, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var status struct {
		NeedsBootstrap bool `json:"needs_bootstrap"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return false, fmt.Errorf("decode: %w", err)
	}
	return status.NeedsBootstrap, nil
}

// newPlainHTTPClient builds an http.Client that respects the standard
// --tls-* flags but performs no authentication — bootstrap is an unauth
// flow by definition. Other CLI subcommands route through the SDK's
// signing client; this one talks plain HTTP because there's no API key
// to sign with yet.
func newPlainHTTPClient(_ *cobra.Command) (*http.Client, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: flagTLSSkipVerify, //nolint:gosec // opt-in via flag
	}
	if flagTLSCA != "" {
		caBytes, err := os.ReadFile(flagTLSCA)
		if err != nil {
			return nil, fmt.Errorf("read tls-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("tls-ca %s: no certificates parsed", flagTLSCA)
		}
		tlsConfig.RootCAs = pool
	}
	if flagTLSCert != "" && flagTLSKey != "" {
		cert, err := tls.LoadX509KeyPair(flagTLSCert, flagTLSKey)
		if err != nil {
			return nil, fmt.Errorf("load mTLS client cert: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

func init() {
	apiKeyCmd.AddCommand(apiKeyBootstrapCmd)
	// Tighten the help output a little so this stands out from the
	// auth-bearing subcommands (create / delete / list / etc).
	apiKeyBootstrapCmd.SetUsageTemplate(apiKeyBootstrapCmd.UsageTemplate() +
		"\nNotes:\n  This subcommand does not require --api-key-id or --api-key-file.\n" +
		"  The /bootstrap endpoint is unauthenticated and only active when api_keys is empty.\n")
	// Silence "Unknown command" suggestions across siblings, since the
	// flow is mostly automated and a stray suggestion is more confusing
	// than helpful.
	apiKeyBootstrapCmd.DisableSuggestions = true
	// Avoid spurious "unused" lint when the os package goes unreferenced
	// after future edits — keep a placeholder reference if needed.
	_ = os.Stdin
}
