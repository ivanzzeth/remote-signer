package evm

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TestSafeRule_SplitRequestFromDB reproduces the failing split request (bc76904b) with
// exact payload and Polymarket Safe rule config to get the actual script reason.
func TestSafeRule_SplitRequestFromDB(t *testing.T) {
	// Payload from sign_requests for request bc76904b (typed_data SafeTx split to CTF)
	payload := []byte(`{"typed_data":{"types":{"SafeTx":[{"name":"to","type":"address"},{"name":"value","type":"uint256"},{"name":"data","type":"bytes"},{"name":"operation","type":"uint8"},{"name":"safeTxGas","type":"uint256"},{"name":"baseGas","type":"uint256"},{"name":"gasPrice","type":"uint256"},{"name":"gasToken","type":"address"},{"name":"refundReceiver","type":"address"},{"name":"nonce","type":"uint256"}],"EIP712Domain":[{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}]},"domain":{"chainId":"137","verifyingContract":"0xac52bebeca7f5fa1561fa9ab8da136602d21b837"},"message":{"to":"0x4D97DCd97eC945f40cF65F87097ACe5EA0476045","data":"0x72ce42750000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa841740000000000000000000000000000000000000000000000000000000000000000348959679f78cbdfcbca76e83affad0ea89e77ac32d03273552da0cb85d3042a00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000f4240000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002","nonce":"27","value":"0","baseGas":"0","gasPrice":"0","gasToken":"0x0000000000000000000000000000000000000000","operation":"0","safeTxGas":"307467","refundReceiver":"0x0000000000000000000000000000000000000000"},"primaryType":"SafeTx"}}`)

	req := &types.SignRequest{
		ID:            "bc76904b-704d-449c-b71b-eb6e58fb78d8",
		ChainID:       "137",
		SignerAddress: "0x88eD75e9eCE373997221E3c0229e74007C1AD718",
		SignType:      SignTypeTypedData,
		Payload:       payload,
	}

	ruleInput, err := BuildRuleInput(req, nil)
	require.NoError(t, err)
	require.NotNil(t, ruleInput.TypedData, "typed_data required")
	require.Equal(t, "SafeTx", ruleInput.TypedData.PrimaryType)

	// Load Safe template and extract whitelist rule script (Safe SafeTx and execTransaction)
	repoRoot := findRepoRoot(t)
	templatePath := filepath.Join(repoRoot, "rules", "templates", "safe.template.js.yaml")
	data, err := os.ReadFile(templatePath)
	require.NoError(t, err)

	var template struct {
		Rules []struct {
			Name   string `yaml:"name"`
			Config struct {
				Script string `yaml:"script"`
			} `yaml:"config"`
		} `yaml:"rules"`
	}
	require.NoError(t, yaml.Unmarshal(data, &template))

	var safeScript string
	for _, r := range template.Rules {
		if r.Name == "Safe SafeTx and execTransaction" && r.Config.Script != "" {
			safeScript = r.Config.Script
			break
		}
	}
	require.NotEmpty(t, safeScript, "Safe SafeTx script not found in template")

	// Polymarket Safe instance variables from config.yaml
	config := map[string]interface{}{
		"chain_id":                     "137",
		"allowed_safe_addresses":       "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837",
		"allowed_safe_tx_to_addresses": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174,0x4D97DCd97eC945f40cF65F87097ACe5EA0476045,0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296,0xC5d563A36AE78145C45a50134d48A1215220f80a",
		"delegate_to":                  "polymarket#transactions",
	}

	e, err := NewJSRuleEvaluator(slog.Default())
	require.NoError(t, err)

	res := e.wrappedValidate(safeScript, ruleInput, config, nil)

	t.Logf("Valid=%v Reason=%q", res.Valid, res.Reason)
	if !res.Valid {
		t.Errorf("Safe rule rejected: %s", res.Reason)
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "rules", "templates", "safe.template.js.yaml")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repo root not found (rules/templates/safe.template.js.yaml)")
		}
		dir = parent
	}
}
