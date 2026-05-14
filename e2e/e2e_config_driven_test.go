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
	"strings"
	"testing"
	"time"

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
	ensureGuardResumed(t)
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

// TestConfigDriven_ERC20InstanceHasBudget verifies that the ERC20 instance in config.e2e.yaml
// (with budget and schedule) gets budget records on server sync, so budget enforcement runs.
func TestConfigDriven_ERC20InstanceHasBudget(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("config-driven test uses config.e2e.yaml rules")
	}
	ctx := context.Background()
	unit := "1:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
	t.Logf("[ERC20InstanceHasBudget] step 1: listing rules")
	listResp, err := adminClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.NoError(t, err, "list rules")
	t.Logf("[ERC20InstanceHasBudget] step 2: got %d rules, iterating for ERC20 transfer/approve", len(listResp.Rules))
	var foundBudget bool
	for _, r := range listResp.Rules {
		if r.Name != "ERC20 transfer/transferFrom limit" && r.Name != "ERC20 approve limit" {
			continue
		}
		t.Logf("[ERC20InstanceHasBudget] step 3: rule id=%s name=%s, listing budgets", r.ID, r.Name)
		budgets, err := adminClient.EVM.Rules.ListBudgets(ctx, r.ID)
		if err != nil {
			t.Logf("[ERC20InstanceHasBudget] ListBudgets error for %s: %v", r.ID, err)
			continue
		}
		t.Logf("[ERC20InstanceHasBudget] rule %s has %d budget(s)", r.ID, len(budgets))
		for _, b := range budgets {
			t.Logf("[ERC20InstanceHasBudget] budget unit=%s max_total=%s", b.Unit, b.MaxTotal)
			if strings.EqualFold(b.Unit, unit) {
				foundBudget = true
				require.Equal(t, "1000000000", b.MaxTotal, "max_total from config.e2e.yaml")
				t.Logf("[ERC20InstanceHasBudget] step 4: found budget unit=%s max_total=%s", b.Unit, b.MaxTotal)
				break
			}
		}
		if foundBudget {
			break
		}
	}
	require.True(t, foundBudget, "ERC20 instance with budget in config.e2e.yaml should have at least one budget with unit %q after sync", unit)
}

// TestConfigDriven_ERC20RuleHasSchedule verifies that the ERC20 instance rule has schedule (period 24h) from config.
func TestConfigDriven_ERC20RuleHasSchedule(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("config-driven test uses config.e2e.yaml rules")
	}
	ctx := context.Background()
	t.Logf("[ERC20RuleHasSchedule] step 1: listing rules")
	listResp, err := adminClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.NoError(t, err, "list rules")
	t.Logf("[ERC20RuleHasSchedule] step 2: got %d rules", len(listResp.Rules))
	var foundSchedule bool
	for _, r := range listResp.Rules {
		if r.Name != "ERC20 transfer/transferFrom limit" && r.Name != "ERC20 approve limit" {
			continue
		}
		t.Logf("[ERC20RuleHasSchedule] rule id=%s BudgetPeriod=%q BudgetPeriodStart=%v", r.ID, r.BudgetPeriod, r.BudgetPeriodStart != nil)
		if r.BudgetPeriod != "" && (strings.Contains(r.ID, "erc20_") || r.ID == "erc20") && !strings.Contains(r.ID, "erc20-schedule") {
			require.Contains(t, r.BudgetPeriod, "24h", "ERC20 instance rule should have schedule period 24h")
			require.NotNil(t, r.BudgetPeriodStart, "ERC20 instance rule should have budget_period_start")
			foundSchedule = true
			t.Logf("[ERC20RuleHasSchedule] step 3: found schedule rule id=%s", r.ID)
			break
		}
	}
	require.True(t, foundSchedule, "at least one ERC20 instance rule should have schedule (budget_period 24h)")
}

const (
	erc20ScheduleToken    = "0x0000000000000000000000000000000000000001"
	erc20ScheduleUnit     = "1:0x0000000000000000000000000000000000000001"
	erc20ScheduleSigner   = erc20BudgetSigner
	erc20ScheduleRecipient = erc20BudgetRecipient
)

// TestConfigDriven_Schedule_PeriodReset verifies that budget is reset at period boundary: spend, wait for new period, spend again.
// Uses the "ERC20 schedule (1s)" instance (period 1s); after 2s the budget resets so a second transfer succeeds and spent is 100.
func TestConfigDriven_Schedule_PeriodReset(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("config-driven test uses config.e2e.yaml rules")
	}
	ctx := context.Background()
	t.Logf("[Schedule_PeriodReset] step 1: listing rules")
	listResp, err := adminClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.NoError(t, err, "list rules")
	t.Logf("[Schedule_PeriodReset] step 2: got %d rules", len(listResp.Rules))
	var scheduleRuleID string
	for _, r := range listResp.Rules {
		if r.Name == "ERC20 transfer/transferFrom limit" && strings.Contains(r.ID, "erc20-schedule") {
			scheduleRuleID = r.ID
			break
		}
	}
	require.NotEmpty(t, scheduleRuleID, "ERC20 schedule (1s) transfer rule should exist")
	t.Logf("[Schedule_PeriodReset] step 3: schedule rule id=%s", scheduleRuleID)

	sendTransfer := func(amount int64) error {
		data := erc20TransferData(erc20ScheduleRecipient, big.NewInt(amount))
		txPayload := map[string]interface{}{
			"transaction": map[string]interface{}{
				"from": erc20ScheduleSigner, "to": erc20ScheduleToken, "value": "0", "data": data,
				"gas": 21000, "gasPrice": "0", "txType": "legacy",
			},
		}
		payloadBytes, err := json.Marshal(txPayload)
		if err != nil {
			return err
		}
		req := &evm.SignRequest{
			ChainID:       "1",
			SignerAddress: erc20ScheduleSigner,
			SignType:      "transaction",
			Payload:       payloadBytes,
		}
		_, err = adminClient.EVM.Sign.Execute(ctx, req)
		return err
	}

	t.Logf("[Schedule_PeriodReset] step 4: sending first transfer 100")
	require.NoError(t, sendTransfer(100), "first transfer (100) should succeed")
	t.Logf("[Schedule_PeriodReset] step 5: listing budgets after first transfer")
	budgets, err := adminClient.EVM.Rules.ListBudgets(ctx, scheduleRuleID)
	require.NoError(t, err)
	var spentAfterFirst string
	for _, b := range budgets {
		if b.Unit == erc20ScheduleUnit {
			spentAfterFirst = b.Spent
			break
		}
	}
	require.Equal(t, "100", spentAfterFirst, "spent should be 100 after first transfer")
	t.Logf("[Schedule_PeriodReset] step 6: sleeping 2s for period reset")
	time.Sleep(2 * time.Second) // next period (1s) so budget resets
	t.Logf("[Schedule_PeriodReset] step 7: sending second transfer 100")
	require.NoError(t, sendTransfer(100), "second transfer after period reset should succeed")
	t.Logf("[Schedule_PeriodReset] step 8: listing budgets after second transfer")
	budgets, err = adminClient.EVM.Rules.ListBudgets(ctx, scheduleRuleID)
	require.NoError(t, err)
	for _, b := range budgets {
		if b.Unit == erc20ScheduleUnit {
			require.Equal(t, "100", b.Spent, "spent should be 100 after reset (0 + 100), not 200")
			t.Logf("[Schedule_PeriodReset] step 9: done, spent=%s", b.Spent)
			return
		}
	}
	t.Fatal("no budget found for erc20-schedule unit after second transfer")
}

// erc20TransferData returns calldata for transfer(address to, uint256 amount). Selector 0xa9059cbb.
func erc20TransferData(recipient string, amount *big.Int) string {
	if amount == nil {
		amount = big.NewInt(0)
	}
	toHex := recipient
	if len(toHex) >= 2 && toHex[:2] == "0x" {
		toHex = toHex[2:]
	}
	for len(toHex) < 64 {
		toHex = "0" + toHex
	}
	if len(toHex) > 64 {
		toHex = toHex[len(toHex)-64:]
	}
	amtHex := fmt.Sprintf("%064x", amount)
	if len(amtHex) > 64 {
		amtHex = amtHex[len(amtHex)-64:]
	}
	return "0xa9059cbb" + toHex + amtHex
}

const (
	erc20BudgetToken    = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
	erc20BudgetRecipient = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
	erc20BudgetUnit     = "1:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
	erc20BudgetSigner   = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

	// Tokens for additional budget e2e (max_tx_count, max_per_tx=0, -1 unlimited)
	erc20TxCountToken     = "0x0000000000000000000000000000000000000002"
	erc20ZeroPerTxToken   = "0x0000000000000000000000000000000000000003"
	erc20PerTxUnlimited   = "0x0000000000000000000000000000000000000004"
	erc20TotalUnlimited   = "0x0000000000000000000000000000000000000005"
)

// TestConfigDriven_ERC20Budget_DeductedOnSign signs one ERC20 transfer (amount 100); expects success and budget spent increases.
func TestConfigDriven_ERC20Budget_DeductedOnSign(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("config-driven test uses config.e2e.yaml rules")
	}
	ctx := context.Background()
	t.Logf("[ERC20Budget_DeductedOnSign] step 1: building and sending sign request (amount 100)")
	data := erc20TransferData(erc20BudgetRecipient, big.NewInt(100))
	txPayload := map[string]interface{}{
		"transaction": map[string]interface{}{
			"from": erc20BudgetSigner, "to": erc20BudgetToken, "value": "0", "data": data,
			"gas": 21000, "gasPrice": "0", "txType": "legacy",
		},
	}
	payloadBytes, err := json.Marshal(txPayload)
	require.NoError(t, err)
	req := &evm.SignRequest{
		ChainID:       "1",
		SignerAddress: erc20BudgetSigner,
		SignType:      "transaction",
		Payload:       payloadBytes,
	}
	resp, err := adminClient.EVM.Sign.Execute(ctx, req)
	require.NoError(t, err, "ERC20 transfer under cap should succeed")
	require.NotNil(t, resp)
	require.Equal(t, "completed", resp.Status)
	t.Logf("[ERC20Budget_DeductedOnSign] step 2: sign completed, listing rules")

	listResp, err := adminClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.NoError(t, err)
	t.Logf("[ERC20Budget_DeductedOnSign] step 3: got %d rules, checking budgets for unit %s", len(listResp.Rules), erc20BudgetUnit)
	// Find the transfer rule that has a budget with the USDC unit (erc20_erc20-transfer-limit, not the schedule one).
	var found bool
	for _, r := range listResp.Rules {
		if r.Name != "ERC20 transfer/transferFrom limit" {
			continue
		}
		budgets, err := adminClient.EVM.Rules.ListBudgets(ctx, r.ID)
		if err != nil {
			continue
		}
		for _, b := range budgets {
			if strings.EqualFold(b.Unit, erc20BudgetUnit) {
				require.Equal(t, "100", b.Spent, "budget spent should be 100 after one transfer(100) for rule %s", r.ID)
				t.Logf("[ERC20Budget_DeductedOnSign] step 4: found budget spent=%s for rule %s", b.Spent, r.ID)
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	require.True(t, found, "no budget found with expected unit after sign")
}

// TestConfigDriven_ERC20Budget_RejectedWhenPerTxExceeded signs transfer(amount 1000000001) which exceeds max_per_tx 1000000000.
// Amounts are in token smallest unit (USDC 6 decimals: 1000000000 = 1000 USDC). Config and test use same convention.
func TestConfigDriven_ERC20Budget_RejectedWhenPerTxExceeded(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("config-driven test uses config.e2e.yaml rules")
	}
	ctx := context.Background()
	t.Logf("[ERC20Budget_RejectedWhenPerTxExceeded] step 1: sending transfer amount 1000000001 (over max_per_tx)")
	data := erc20TransferData(erc20BudgetRecipient, big.NewInt(1000000001))
	txPayload := map[string]interface{}{
		"transaction": map[string]interface{}{
			"from": erc20BudgetSigner, "to": erc20BudgetToken, "value": "0", "data": data,
			"gas": 21000, "gasPrice": "0", "txType": "legacy",
		},
	}
	payloadBytes, err := json.Marshal(txPayload)
	require.NoError(t, err)
	req := &evm.SignRequest{
		ChainID:       "1",
		SignerAddress: erc20BudgetSigner,
		SignType:      "transaction",
		Payload:       payloadBytes,
	}
	resp, err := adminClient.EVM.Sign.Execute(ctx, req)
	t.Logf("[ERC20Budget_RejectedWhenPerTxExceeded] step 2: sign returned err=%v resp=%v", err, resp != nil)
	require.Error(t, err, "transfer over max_per_tx should be rejected")
	require.Nil(t, resp)
}

// TestConfigDriven_ERC20Budget_RejectedWhenTotalExceeded exhausts budget with two transfers, then third is rejected.
// Uses 499999950 each so that if DeductedOnSign already ran (spent 100), total 100+499999950+499999950 = 999999900+100 = 1000000000; then +1 exceeds.
func TestConfigDriven_ERC20Budget_RejectedWhenTotalExceeded(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("config-driven test uses config.e2e.yaml rules")
	}
	ctx := context.Background()
	sendTransfer := func(amount int64) (err error) {
		data := erc20TransferData(erc20BudgetRecipient, big.NewInt(amount))
		txPayload := map[string]interface{}{
			"transaction": map[string]interface{}{
				"from": erc20BudgetSigner, "to": erc20BudgetToken, "value": "0", "data": data,
				"gas": 21000, "gasPrice": "0", "txType": "legacy",
			},
		}
		payloadBytes, _ := json.Marshal(txPayload)
		req := &evm.SignRequest{
			ChainID:       "1",
			SignerAddress: erc20BudgetSigner,
			SignType:      "transaction",
			Payload:       payloadBytes,
		}
		_, err = adminClient.EVM.Sign.Execute(ctx, req)
		return err
	}
	const half = 499999950 // two halfs = 999999900; with 0 or 100 prior spent, 999999900 leaves 100 or 0 headroom
	t.Logf("[ERC20Budget_RejectedWhenTotalExceeded] step 1: first transfer amount=%d", half)
	require.NoError(t, sendTransfer(half), "first transfer should pass")
	t.Logf("[ERC20Budget_RejectedWhenTotalExceeded] step 2: second transfer amount=%d", half)
	require.NoError(t, sendTransfer(half), "second transfer should pass")
	t.Logf("[ERC20Budget_RejectedWhenTotalExceeded] step 3: third transfer amount=101 (expect reject)")
	require.Error(t, sendTransfer(101), "third transfer (101) should be rejected: total would exceed max_total 1000000000")
	t.Logf("[ERC20Budget_RejectedWhenTotalExceeded] step 4: done")
}

// TestConfigDriven_ERC20Budget_RejectedWhenTxCountExceeded uses the "ERC20 instance (tx count)" with max_tx_count=2:
// two transfers succeed, the third is rejected by AtomicSpend (tx_count >= max_tx_count).
func TestConfigDriven_ERC20Budget_RejectedWhenTxCountExceeded(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("config-driven test uses config.e2e.yaml rules")
	}
	ctx := context.Background()
	sendTransfer := func(token string) error {
		data := erc20TransferData(erc20BudgetRecipient, big.NewInt(1))
		txPayload := map[string]interface{}{
			"transaction": map[string]interface{}{
				"from": erc20BudgetSigner, "to": token, "value": "0", "data": data,
				"gas": 21000, "gasPrice": "0", "txType": "legacy",
			},
		}
		payloadBytes, _ := json.Marshal(txPayload)
		req := &evm.SignRequest{
			ChainID:       "1",
			SignerAddress: erc20BudgetSigner,
			SignType:      "transaction",
			Payload:       payloadBytes,
		}
		_, err := adminClient.EVM.Sign.Execute(ctx, req)
		return err
	}
	t.Logf("[ERC20Budget_RejectedWhenTxCountExceeded] step 1: first transfer (expect pass)")
	require.NoError(t, sendTransfer(erc20TxCountToken), "first transfer should pass")
	t.Logf("[ERC20Budget_RejectedWhenTxCountExceeded] step 2: second transfer (expect pass)")
	require.NoError(t, sendTransfer(erc20TxCountToken), "second transfer should pass")
	t.Logf("[ERC20Budget_RejectedWhenTxCountExceeded] step 3: third transfer (expect reject: tx_count exceeded)")
	require.Error(t, sendTransfer(erc20TxCountToken), "third transfer should be rejected: max_tx_count=2 exceeded")
}

// TestConfigDriven_ERC20Budget_RejectedWhenMaxPerTxZero uses the "ERC20 instance (per-tx zero)" with max_per_tx=0:
// any single transfer is rejected by CheckAndDeductBudget (amount > 0 when max_per_tx is 0).
func TestConfigDriven_ERC20Budget_RejectedWhenMaxPerTxZero(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("config-driven test uses config.e2e.yaml rules")
	}
	ctx := context.Background()
	data := erc20TransferData(erc20BudgetRecipient, big.NewInt(1))
	txPayload := map[string]interface{}{
		"transaction": map[string]interface{}{
			"from": erc20BudgetSigner, "to": erc20ZeroPerTxToken, "value": "0", "data": data,
			"gas": 21000, "gasPrice": "0", "txType": "legacy",
		},
	}
	payloadBytes, err := json.Marshal(txPayload)
	require.NoError(t, err)
	req := &evm.SignRequest{
		ChainID:       "1",
		SignerAddress: erc20BudgetSigner,
		SignType:      "transaction",
		Payload:       payloadBytes,
	}
	resp, err := adminClient.EVM.Sign.Execute(ctx, req)
	t.Logf("[ERC20Budget_RejectedWhenMaxPerTxZero] sign returned err=%v resp=%v", err, resp != nil)
	require.Error(t, err, "transfer with max_per_tx=0 should be rejected")
	require.Nil(t, resp)
}

// TestConfigDriven_ERC20Budget_AllowedWhenMaxPerTxUnlimited uses "ERC20 instance (per-tx unlimited)" with max_per_tx="-1":
// a single transfer up to max_total (1000000) is allowed (no per-tx cap).
func TestConfigDriven_ERC20Budget_AllowedWhenMaxPerTxUnlimited(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("config-driven test uses config.e2e.yaml rules")
	}
	ctx := context.Background()
	amount := int64(1000000) // equals max_total; max_per_tx=-1 so no per-tx rejection
	data := erc20TransferData(erc20BudgetRecipient, big.NewInt(amount))
	txPayload := map[string]interface{}{
		"transaction": map[string]interface{}{
			"from": erc20BudgetSigner, "to": erc20PerTxUnlimited, "value": "0", "data": data,
			"gas": 21000, "gasPrice": "0", "txType": "legacy",
		},
	}
	payloadBytes, err := json.Marshal(txPayload)
	require.NoError(t, err)
	req := &evm.SignRequest{
		ChainID:       "1",
		SignerAddress: erc20BudgetSigner,
		SignType:      "transaction",
		Payload:       payloadBytes,
	}
	resp, err := adminClient.EVM.Sign.Execute(ctx, req)
	t.Logf("[ERC20Budget_AllowedWhenMaxPerTxUnlimited] sign amount=%d (max_per_tx=-1) err=%v resp=%v", amount, err, resp != nil)
	require.NoError(t, err, "transfer with max_per_tx=-1 should be allowed up to max_total")
	require.NotNil(t, resp)
	require.Equal(t, "completed", resp.Status)
}

// TestConfigDriven_ERC20Budget_AllowedWhenMaxTotalUnlimited uses "ERC20 instance (total unlimited)" with max_total="-1":
// multiple transfers succeed (no total cap).
func TestConfigDriven_ERC20Budget_AllowedWhenMaxTotalUnlimited(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("config-driven test uses config.e2e.yaml rules")
	}
	ctx := context.Background()
	sendTransfer := func() error {
		data := erc20TransferData(erc20BudgetRecipient, big.NewInt(100))
		txPayload := map[string]interface{}{
			"transaction": map[string]interface{}{
				"from": erc20BudgetSigner, "to": erc20TotalUnlimited, "value": "0", "data": data,
				"gas": 21000, "gasPrice": "0", "txType": "legacy",
			},
		}
		payloadBytes, _ := json.Marshal(txPayload)
		req := &evm.SignRequest{
			ChainID:       "1",
			SignerAddress: erc20BudgetSigner,
			SignType:      "transaction",
			Payload:       payloadBytes,
		}
		_, err := adminClient.EVM.Sign.Execute(ctx, req)
		return err
	}
	for i := 1; i <= 3; i++ {
		t.Logf("[ERC20Budget_AllowedWhenMaxTotalUnlimited] transfer %d/3 (max_total=-1)", i)
		require.NoError(t, sendTransfer(), "transfer %d with max_total=-1 should be allowed", i)
	}
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
