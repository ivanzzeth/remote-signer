//go:build e2e
package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// =============================================================================

// TestJavaScriptClientE2E runs the JavaScript client's e2e tests against the test server
func TestJavaScriptClientE2E(t *testing.T) {
	// Skip if running in external server mode (server not started by us)
	if useExternalServer {
		t.Skip("Skipping JavaScript client e2e tests in external server mode")
	}

	// Get the project root directory
	projectRoot, err := os.Getwd()
	require.NoError(t, err)
	// Go up from e2e/ to project root
	for !strings.HasSuffix(projectRoot, "remote-signer") && len(projectRoot) > 1 {
		projectRoot = filepath.Dir(projectRoot)
	}
	require.True(t, strings.HasSuffix(projectRoot, "remote-signer"), "Could not find project root")

	jsClientDir := filepath.Join(projectRoot, "pkg", "js-client")

	// Check if js-client directory exists
	if _, err := os.Stat(jsClientDir); os.IsNotExist(err) {
		t.Skipf("JavaScript client directory not found at %s, skipping test", jsClientDir)
	}

	// Check if node_modules exists (dependencies installed)
	nodeModulesPath := filepath.Join(jsClientDir, "node_modules")
	if _, err := os.Stat(nodeModulesPath); os.IsNotExist(err) {
		t.Skipf("JavaScript client dependencies not installed at %s, skipping test. Run 'npm install' in %s", nodeModulesPath, jsClientDir)
	}

	// Set up environment variables for JavaScript tests
	env := os.Environ()
	env = append(env, "E2E_EXTERNAL_SERVER=true")
	env = append(env, fmt.Sprintf("E2E_BASE_URL=%s", baseURL))
	env = append(env, fmt.Sprintf("E2E_API_KEY_ID=%s", adminAPIKeyID))
	env = append(env, fmt.Sprintf("E2E_PRIVATE_KEY=%s", adminAPIKeyHex))
	env = append(env, fmt.Sprintf("E2E_SIGNER_ADDRESS=%s", testSignerAddress))

	// Parse chain ID
	chainIDInt, err := strconv.Atoi(testChainID)
	if err != nil {
		chainIDInt = 1 // Default to 1
	}
	env = append(env, fmt.Sprintf("E2E_CHAIN_ID=%d", chainIDInt))

	// Run JavaScript e2e tests
	cmd := exec.Command("npm", "run", "test:e2e")
	cmd.Dir = jsClientDir
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	t.Logf("Running JavaScript client e2e tests...")
	t.Logf("  Base URL: %s", baseURL)
	t.Logf("  API Key ID: %s", adminAPIKeyID)
	t.Logf("  Working directory: %s", jsClientDir)

	err = cmd.Run()
	require.NoError(t, err, "JavaScript client e2e tests failed")
}

// TestMetaMaskSnapE2E runs the MetaMask Snap's e2e tests against the test server
func TestMetaMaskSnapE2E(t *testing.T) {
	// Skip if running in external server mode (server not started by us)
	if useExternalServer {
		t.Skip("Skipping MetaMask Snap e2e tests in external server mode")
	}

	// Get the project root directory
	projectRoot, err := os.Getwd()
	require.NoError(t, err)
	// Go up from e2e/ to project root
	for !strings.HasSuffix(projectRoot, "remote-signer") && len(projectRoot) > 1 {
		projectRoot = filepath.Dir(projectRoot)
	}
	require.True(t, strings.HasSuffix(projectRoot, "remote-signer"), "Could not find project root")

	snapDir := filepath.Join(projectRoot, "app", "metamask-snap")

	// Check if snap directory exists
	if _, err := os.Stat(snapDir); os.IsNotExist(err) {
		t.Skipf("MetaMask Snap directory not found at %s, skipping test", snapDir)
	}

	// Check if node_modules exists (dependencies installed)
	nodeModulesPath := filepath.Join(snapDir, "node_modules")
	if _, err := os.Stat(nodeModulesPath); os.IsNotExist(err) {
		t.Skipf("MetaMask Snap dependencies not installed at %s, skipping test. Run 'npm install' in %s", nodeModulesPath, snapDir)
	}

	// Set up environment variables for Snap tests
	env := os.Environ()
	env = append(env, "E2E_EXTERNAL_SERVER=true")
	env = append(env, fmt.Sprintf("E2E_BASE_URL=%s", baseURL))
	env = append(env, fmt.Sprintf("E2E_API_KEY_ID=%s", adminAPIKeyID))
	env = append(env, fmt.Sprintf("E2E_PRIVATE_KEY=%s", adminAPIKeyHex))
	env = append(env, fmt.Sprintf("E2E_SIGNER_ADDRESS=%s", testSignerAddress))

	// Parse chain ID
	chainIDInt, err := strconv.Atoi(testChainID)
	if err != nil {
		chainIDInt = 1 // Default to 1
	}
	env = append(env, fmt.Sprintf("E2E_CHAIN_ID=%d", chainIDInt))

	// Run MetaMask Snap e2e tests
	cmd := exec.Command("npm", "run", "test:e2e")
	cmd.Dir = snapDir
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	t.Logf("Running MetaMask Snap e2e tests...")
	t.Logf("  Base URL: %s", baseURL)
	t.Logf("  API Key ID: %s", adminAPIKeyID)
	t.Logf("  Working directory: %s", snapDir)

	err = cmd.Run()
	require.NoError(t, err, "MetaMask Snap e2e tests failed")
}
