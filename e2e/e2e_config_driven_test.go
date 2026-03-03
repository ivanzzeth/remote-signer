//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// TestConfigDrivenRuleValidation loads test cases from config.e2e.yaml and submits them
// through the HTTP sign API, verifying expected pass/fail results.
// This ensures real transaction data is validated through the full HTTP stack.
func TestConfigDrivenRuleValidation(t *testing.T) {
	if useExternalServer {
		t.Skip("config-driven test uses config.e2e.yaml rules")
	}

	ctx := context.Background()

	// Load config.e2e.yaml
	configPath := findConfigPath()
	cfg, err := config.Load(configPath)
	require.NoError(t, err, "failed to load config.e2e.yaml")

	// Expand instance rules (templates + test_cases_overrides)
	expandedRules, err := expandRulesFromConfig(cfg, configPath)
	require.NoError(t, err, "failed to expand instance rules")

	tested := 0
	for _, rule := range expandedRules {
		if len(rule.TestCases) == 0 {
			continue
		}
		for _, tc := range rule.TestCases {
			tc := tc // capture loop variable
			ruleName := rule.Name
			t.Run(ruleName+"/"+tc.Name, func(t *testing.T) {
				req, err := testCaseInputToSignRequest(tc.Input)
				require.NoError(t, err, "failed to convert test case input to sign request")

				resp, signErr := adminClient.EVM.Sign.Execute(ctx, req)
				if tc.ExpectPass {
					require.NoError(t, signErr, "expected pass but got error for %s/%s", ruleName, tc.Name)
					require.NotNil(t, resp, "expected non-nil response for %s/%s", ruleName, tc.Name)
					require.Equal(t, "completed", resp.Status, "expected completed status for %s/%s", ruleName, tc.Name)
				} else {
					require.Error(t, signErr, "expected reject but got success for %s/%s", ruleName, tc.Name)
				}
			})
			tested++
		}
	}
	require.Greater(t, tested, 0, "should have tested at least one config-driven test case")
	t.Logf("config-driven: tested %d test cases across all rules", tested)
}

// findConfigPath locates config.e2e.yaml by walking up from the current directory.
func findConfigPath() string {
	configPath := "config.e2e.yaml"
	wd, err := os.Getwd()
	if err != nil {
		return configPath
	}
	for wd != "/" && wd != "" {
		testPath := filepath.Join(wd, configPath)
		if _, err := os.Stat(testPath); err == nil {
			return testPath
		}
		wd = filepath.Dir(wd)
	}
	return configPath
}

// expandRulesFromConfig loads templates and expands instance rules, returning all rules with test cases.
func expandRulesFromConfig(cfg *config.Config, configPath string) ([]config.RuleConfig, error) {
	if len(cfg.Templates) == 0 {
		return cfg.Rules, nil
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
	configDir := filepath.Dir(configPath)

	// Initialize template repository (in-memory, just for loading)
	templateRepo, err := newInMemoryTemplateRepo()
	if err != nil {
		return nil, fmt.Errorf("failed to create template repo: %w", err)
	}

	templateInit, err := config.NewTemplateInitializer(templateRepo, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create template initializer: %w", err)
	}
	templateInit.SetConfigDir(configDir)

	if err := templateInit.SyncFromConfig(context.Background(), cfg.Templates); err != nil {
		return nil, fmt.Errorf("failed to sync templates: %w", err)
	}

	loadedTemplates, err := templateInit.GetLoadedTemplates(cfg.Templates)
	if err != nil {
		return nil, fmt.Errorf("failed to get loaded templates: %w", err)
	}

	return config.ExpandInstanceRules(cfg.Rules, loadedTemplates)
}

// testCaseInputToSignRequest converts a YAML test case input map to an evm.SignRequest.
// It fills in required HTTP API fields (types, gas, txType) that rule-engine-level test cases omit.
func testCaseInputToSignRequest(input map[string]interface{}) (*evm.SignRequest, error) {
	signType := stringFromMap(input, "sign_type")
	chainID := stringFromMap(input, "chain_id")
	signer := stringFromMap(input, "signer")

	if signType == "" {
		signType = "transaction"
	}
	if chainID == "" {
		chainID = "1"
	}

	req := &evm.SignRequest{
		ChainID:      chainID,
		SignerAddress: signer,
		SignType:      signType,
	}

	switch signType {
	case "typed_data":
		td, ok := input["typed_data"]
		if !ok {
			return nil, fmt.Errorf("typed_data input missing 'typed_data' field")
		}
		tdMap, ok := td.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("typed_data must be a map")
		}
		// Ensure types field is present (required by HTTP API but not by rule engine)
		ensureTypedDataTypes(tdMap)
		payload := map[string]interface{}{"typed_data": tdMap}
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal typed_data payload: %w", err)
		}
		req.Payload = data

	case "transaction":
		tx, ok := input["transaction"]
		if !ok {
			return nil, fmt.Errorf("transaction input missing 'transaction' field")
		}
		txMap, ok := tx.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("transaction must be a map")
		}
		// Ensure required HTTP API fields
		ensureTransactionDefaults(txMap)
		payload := map[string]interface{}{"transaction": txMap}
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal transaction payload: %w", err)
		}
		req.Payload = data

	case "personal", "eip191", "personal_sign":
		// Map personal_sign to personal for the HTTP API
		req.SignType = "personal"
		// Check for message in multiple possible locations
		msg := stringFromMap(input, "message")
		if msg == "" {
			// Some test cases use personal_sign.message
			if ps, ok := input["personal_sign"].(map[string]interface{}); ok {
				msg = stringFromMap(ps, "message")
			}
		}
		payload := map[string]interface{}{"message": msg}
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal message payload: %w", err)
		}
		req.Payload = data

	case "hash":
		hash := stringFromMap(input, "hash")
		payload := map[string]interface{}{"hash": hash}
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal hash payload: %w", err)
		}
		req.Payload = data

	default:
		return nil, fmt.Errorf("unsupported sign_type: %s", signType)
	}

	return req, nil
}

// ensureTypedDataTypes generates the EIP-712 types field if missing.
// The HTTP API requires types but rule-engine test cases often omit them.
func ensureTypedDataTypes(td map[string]interface{}) {
	if _, ok := td["types"]; ok {
		return
	}

	types := make(map[string]interface{})

	// Generate EIP712Domain type from domain fields
	domain, _ := td["domain"].(map[string]interface{})
	var domainFields []map[string]string
	// Order matters for EIP-712 hash; use canonical order
	for _, pair := range []struct{ key, typ string }{
		{"name", "string"},
		{"version", "string"},
		{"chainId", "uint256"},
		{"verifyingContract", "address"},
		{"salt", "bytes32"},
	} {
		if _, ok := domain[pair.key]; ok {
			domainFields = append(domainFields, map[string]string{"name": pair.key, "type": pair.typ})
		}
	}
	types["EIP712Domain"] = domainFields

	// Generate primaryType fields from message
	primaryType, _ := td["primaryType"].(string)
	if primaryType != "" {
		message, _ := td["message"].(map[string]interface{})
		types[primaryType] = inferFieldTypes(primaryType, message)
	}

	td["types"] = types
}

// knownEIP712Types maps known EIP-712 struct types to their field definitions.
// This ensures correct types for well-known Polymarket/Safe structs.
var knownEIP712Types = map[string][]map[string]string{
	"ClobAuth": {
		{"name": "address", "type": "address"},
		{"name": "timestamp", "type": "string"},
		{"name": "nonce", "type": "uint256"},
		{"name": "message", "type": "string"},
	},
	"Order": {
		{"name": "salt", "type": "uint256"},
		{"name": "maker", "type": "address"},
		{"name": "signer", "type": "address"},
		{"name": "taker", "type": "address"},
		{"name": "tokenId", "type": "uint256"},
		{"name": "makerAmount", "type": "uint256"},
		{"name": "takerAmount", "type": "uint256"},
		{"name": "expiration", "type": "uint256"},
		{"name": "nonce", "type": "uint256"},
		{"name": "feeRateBps", "type": "uint256"},
		{"name": "side", "type": "uint8"},
		{"name": "signatureType", "type": "uint8"},
	},
	"CreateProxy": {
		{"name": "paymentToken", "type": "address"},
		{"name": "payment", "type": "uint256"},
		{"name": "paymentReceiver", "type": "address"},
	},
	"SafeTx": {
		{"name": "to", "type": "address"},
		{"name": "value", "type": "uint256"},
		{"name": "data", "type": "bytes"},
		{"name": "operation", "type": "uint8"},
		{"name": "safeTxGas", "type": "uint256"},
		{"name": "baseGas", "type": "uint256"},
		{"name": "gasPrice", "type": "uint256"},
		{"name": "gasToken", "type": "address"},
		{"name": "refundReceiver", "type": "address"},
		{"name": "nonce", "type": "uint256"},
	},
}

// inferFieldTypes returns EIP-712 field definitions for a primaryType.
// Uses known type definitions when available (filtered to only fields in message),
// otherwise infers from message values.
func inferFieldTypes(primaryType string, message map[string]interface{}) []map[string]string {
	if known, ok := knownEIP712Types[primaryType]; ok {
		// Only include fields that are present in the message
		var filtered []map[string]string
		for _, field := range known {
			if _, exists := message[field["name"]]; exists {
				filtered = append(filtered, field)
			}
		}
		if len(filtered) > 0 {
			return filtered
		}
	}
	// Fallback: infer types from message values
	var fields []map[string]string
	for name, val := range message {
		typ := inferSolidityType(val)
		fields = append(fields, map[string]string{"name": name, "type": typ})
	}
	return fields
}

// inferSolidityType guesses the Solidity type from a Go value.
func inferSolidityType(val interface{}) string {
	switch v := val.(type) {
	case string:
		if len(v) == 42 && v[:2] == "0x" {
			return "address"
		}
		if len(v) > 2 && v[:2] == "0x" {
			return "bytes"
		}
		return "string"
	case bool:
		return "bool"
	case float64, int, int64:
		return "uint256"
	default:
		return "string"
	}
}

// ensureTransactionDefaults fills in required HTTP API transaction fields.
func ensureTransactionDefaults(tx map[string]interface{}) {
	if _, ok := tx["gas"]; !ok {
		tx["gas"] = 21000
	}
	if _, ok := tx["txType"]; !ok {
		tx["txType"] = "legacy"
	}
	if _, ok := tx["gasPrice"]; !ok {
		tx["gasPrice"] = "0"
	}
	// Convert hex value (e.g. "0x0") to decimal string
	if val, ok := tx["value"].(string); ok && len(val) > 2 && val[:2] == "0x" {
		n := new(big.Int)
		if _, success := n.SetString(val[2:], 16); success {
			tx["value"] = n.String()
		}
	}
}

// stringFromMap extracts a string value from a map, handling both string and numeric types.
func stringFromMap(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return fmt.Sprintf("%d", int64(val))
	case int:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

// newInMemoryTemplateRepo creates a GORM-based template repository backed by in-memory SQLite.
func newInMemoryTemplateRepo() (storage.TemplateRepository, error) {
	db, err := gorm.Open(sqlite.Open("file:config_driven_test?mode=memory&cache=shared"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open in-memory db: %w", err)
	}
	if err := db.AutoMigrate(&types.RuleTemplate{}); err != nil {
		return nil, fmt.Errorf("failed to migrate: %w", err)
	}
	return storage.NewGormTemplateRepository(db)
}
