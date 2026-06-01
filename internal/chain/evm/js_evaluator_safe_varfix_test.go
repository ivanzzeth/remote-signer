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

// TestSafeRule_ConfigDrivenByVariables proves — with the EXACT blocked transaction
// from production (request 61aa2f8a) — that the Safe rule's outer "txTo must be
// allowed Safe" decision is driven by the `config` object (which production builds
// from rule.Variables via resolveRuleConfig), NOT by the injected Config keys.
//
// Positive: when allowed_safe_addresses includes the new Safe (as the UI edit put
// into Variables), the rule PASSES and delegates. Negative: without it, we get the
// exact rejection the user observed. This is the evidence that the Variables edit
// already takes effect for evm_js rules and the stale Config field was cosmetic.
func loadSafeExecScript(t *testing.T) string {
	t.Helper()
	repoRoot := findRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "rules", "templates", "evm", "safe.yaml"))
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
	for _, r := range template.Rules {
		if r.Name == "Safe SafeTx and execTransaction" && r.Config.Script != "" {
			return r.Config.Script
		}
	}
	t.Fatal("Safe SafeTx script not found")
	return ""
}

func TestSafeRule_ConfigDrivenByVariables(t *testing.T) {
	// Real blocked execTransaction calldata from production request 61aa2f8a:
	// execTransaction wrapping approve(Native USDC -> CollateralOnramp).
	const blockedData = "0x6a761202000000000000000000000000" +
		"3c499c542cef5e3811e1192ce70d8cc03d5c3359" + // inner to = Native USDC
		"0000000000000000000000000000000000000000000000000000000000000000" + // value
		"0000000000000000000000000000000000000000000000000000000000000140" + // data offset
		"0000000000000000000000000000000000000000000000000000000000000000" + // operation = CALL
		"00000000000000000000000000000000000000000000000000000000002a99d0" + // safeTxGas
		"0000000000000000000000000000000000000000000000000000000000000000" + // baseGas
		"0000000000000000000000000000000000000000000000000000000000000000" + // gasPrice
		"0000000000000000000000000000000000000000000000000000000000000000" + // gasToken
		"0000000000000000000000000000000000000000000000000000000000000000" + // refundReceiver
		"00000000000000000000000000000000000000000000000000000000000001c0" + // sig offset
		"0000000000000000000000000000000000000000000000000000000000000044" + // inner data len = 68
		"095ea7b300000000000000000000000093070a847efef7f70739046a929d47a521f5b8ee" + // approve(onramp,
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" + // max)
		"00000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000041" +
		"29b28b18dc1a6dfdd5554574d624bbc8f337e4e0881d2d237e23ed6d97a340872c7bd8fe059c7199fd956f409d2cfe10de3f28f13ba27643cb8ae37ed8b334b61c00000000000000000000000000000000000000000000000000000000000000"

	const newSafe = "0x8faE526C4cfE0b799003d2110F92C40499c6609f"

	payload := []byte(`{"transaction":{"from":"0x764602FeaD618416E42b48c633d90869fF19759E","to":"` +
		newSafe + `","value":"0","data":"` + blockedData + `","nonce":91,"gas":382186}}`)

	req := &types.SignRequest{
		ID:            "61aa2f8a-e9a1-49e3-8d81-fd8788ed2db8",
		ChainID:       "137",
		SignerAddress: "0x764602FeaD618416E42b48c633d90869fF19759E",
		SignType:      SignTypeTransaction,
		Payload:       payload,
	}
	ruleInput, err := BuildRuleInput(req, nil)
	require.NoError(t, err)

	script := loadSafeExecScript(t)
	e, err := NewJSRuleEvaluator(slog.Default())
	require.NoError(t, err)

	// allowed_safe_tx_to_addresses must include Native USDC (it does in the V2 preset).
	const innerAllow = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359,0x93070a847efEf7F70739046A929D47a521F5B8ee"

	t.Run("new Safe in config -> PASS + delegate (this is what the UI edit to Variables produces)", func(t *testing.T) {
		config := map[string]interface{}{
			"chain_id":                     "137",
			"allowed_safe_addresses":       newSafe + ",0x070c08430cb035322d67533814949725163cbcec",
			"allowed_safe_tx_to_addresses": innerAllow,
			"delegate_to":                  "inst_b0882b21d1173383",
			"delegate_mode":                "single",
		}
		res := e.wrappedValidate(script, ruleInput, config, nil)
		require.True(t, res.Valid, "expected pass, got reason: %s", res.Reason)
		require.Equal(t, "inst_b0882b21d1173383", res.DelegateTo, "should delegate inner approve to V2 transactions")
	})

	t.Run("new Safe NOT in config -> exact rejection the user saw", func(t *testing.T) {
		config := map[string]interface{}{
			"chain_id":                     "137",
			"allowed_safe_addresses":       "0x070c08430cb035322d67533814949725163cbcec",
			"allowed_safe_tx_to_addresses": innerAllow,
			"delegate_to":                  "inst_b0882b21d1173383",
			"delegate_mode":                "single",
		}
		res := e.wrappedValidate(script, ruleInput, config, nil)
		require.False(t, res.Valid)
		require.Contains(t, res.Reason, "txTo must be allowed Safe")
	})
}
