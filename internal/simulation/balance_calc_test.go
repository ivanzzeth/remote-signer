package simulation

import (
	"math/big"
	"testing"
)

func TestComputeBalanceChanges_NativeTransfer(t *testing.T) {
	events := []SimEvent{}
	from := "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	to := "0x5e1f62dac767b0491e3ce72469c217365d5b48cc"
	value := "0xde0b6b3a7640000" // 1 ETH

	changes := ComputeBalanceChanges(events, from, to, value)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}

	c := changes[0]
	if c.Token != "native" {
		t.Errorf("expected native, got %s", c.Token)
	}
	if c.Standard != "native" {
		t.Errorf("expected standard native, got %s", c.Standard)
	}
	expected := new(big.Int)
	expected.SetString("1000000000000000000", 10)
	expected.Neg(expected) // outflow
	if c.Amount.Cmp(expected) != 0 {
		t.Errorf("expected amount %s, got %s", expected.String(), c.Amount.String())
	}
	if c.Direction != "outflow" {
		t.Errorf("expected outflow, got %s", c.Direction)
	}
}

func TestComputeBalanceChanges_ERC20TransferOut(t *testing.T) {
	events := []SimEvent{
		{
			Address:  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
			Event:    "Transfer",
			Standard: "erc20",
			Args: map[string]string{
				"from":  "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
				"to":    "0x5e1f62dac767b0491e3ce72469c217365d5b48cc",
				"value": "2300000000",
			},
		},
	}

	changes := ComputeBalanceChanges(events, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "", "")
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}

	c := changes[0]
	if c.Token != "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" {
		t.Errorf("unexpected token: %s", c.Token)
	}
	if c.Standard != "erc20" {
		t.Errorf("expected erc20, got %s", c.Standard)
	}
	expected := big.NewInt(-2300000000)
	if c.Amount.Cmp(expected) != 0 {
		t.Errorf("expected amount %s, got %s", expected.String(), c.Amount.String())
	}
	if c.Direction != "outflow" {
		t.Errorf("expected outflow, got %s", c.Direction)
	}
}

func TestComputeBalanceChanges_ERC20TransferIn(t *testing.T) {
	events := []SimEvent{
		{
			Address:  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
			Event:    "Transfer",
			Standard: "erc20",
			Args: map[string]string{
				"from":  "0x5e1f62dac767b0491e3ce72469c217365d5b48cc",
				"to":    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
				"value": "500000000",
			},
		},
	}

	changes := ComputeBalanceChanges(events, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "", "")
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}

	c := changes[0]
	expected := big.NewInt(500000000)
	if c.Amount.Cmp(expected) != 0 {
		t.Errorf("expected amount %s, got %s", expected.String(), c.Amount.String())
	}
	if c.Direction != "inflow" {
		t.Errorf("expected inflow, got %s", c.Direction)
	}
}

func TestComputeBalanceChanges_SwapOutAndIn(t *testing.T) {
	signer := "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	events := []SimEvent{
		{
			// USDC out
			Address:  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
			Event:    "Transfer",
			Standard: "erc20",
			Args: map[string]string{
				"from":  signer,
				"to":    "0x5e1f62dac767b0491e3ce72469c217365d5b48cc",
				"value": "2300000000",
			},
		},
		{
			// WETH in
			Address:  "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
			Event:    "Transfer",
			Standard: "erc20",
			Args: map[string]string{
				"from":  "0x5e1f62dac767b0491e3ce72469c217365d5b48cc",
				"to":    signer,
				"value": "980000000000000000",
			},
		},
	}

	changes := ComputeBalanceChanges(events, signer, "", "")
	if len(changes) != 2 {
		t.Fatalf("expected 2 changes, got %d", len(changes))
	}

	// Find USDC and WETH changes
	var usdcChange, wethChange *BalanceChange
	for i := range changes {
		switch changes[i].Token {
		case "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48":
			usdcChange = &changes[i]
		case "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2":
			wethChange = &changes[i]
		}
	}

	if usdcChange == nil {
		t.Fatal("USDC change not found")
	}
	if usdcChange.Direction != "outflow" {
		t.Errorf("expected USDC outflow, got %s", usdcChange.Direction)
	}

	if wethChange == nil {
		t.Fatal("WETH change not found")
	}
	if wethChange.Direction != "inflow" {
		t.Errorf("expected WETH inflow, got %s", wethChange.Direction)
	}
}

func TestComputeBalanceChanges_WETHNeutral(t *testing.T) {
	// WETH deposit/withdrawal should NOT produce balance changes
	events := []SimEvent{
		{
			Address:  "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
			Event:    "Deposit",
			Standard: "weth",
			Args: map[string]string{
				"dst": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
				"wad": "1000000000000000000",
			},
		},
	}

	changes := ComputeBalanceChanges(events, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "", "")
	if len(changes) != 0 {
		t.Errorf("expected 0 changes for WETH deposit (neutral), got %d", len(changes))
	}
}

func TestComputeBalanceChanges_ZeroValue(t *testing.T) {
	events := []SimEvent{}
	changes := ComputeBalanceChanges(events, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "", "0x0")
	if len(changes) != 0 {
		t.Errorf("expected 0 changes for zero value, got %d", len(changes))
	}
}

func TestComputeBalanceChanges_ERC721(t *testing.T) {
	signer := "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	events := []SimEvent{
		{
			Address:  "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d",
			Event:    "Transfer",
			Standard: "erc721",
			Args: map[string]string{
				"from":    signer,
				"to":      "0x5e1f62dac767b0491e3ce72469c217365d5b48cc",
				"tokenId": "100",
			},
		},
	}

	changes := ComputeBalanceChanges(events, signer, "", "")
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}

	c := changes[0]
	if c.Standard != "erc721" {
		t.Errorf("expected erc721, got %s", c.Standard)
	}
	if c.TokenID == nil || c.TokenID.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("expected tokenID 100, got %v", c.TokenID)
	}
	if c.Direction != "outflow" {
		t.Errorf("expected outflow, got %s", c.Direction)
	}
}

func TestComputeNetBalanceChanges_BatchApproveSwap(t *testing.T) {
	signer := "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"

	// tx0: approve (no balance change)
	result0 := SimulationResult{
		Success:        true,
		GasUsed:        46000,
		BalanceChanges: []BalanceChange{},
		HasApproval:    true,
	}

	// tx1: swap (USDC out, ETH in)
	result1 := SimulationResult{
		Success: true,
		GasUsed: 285000,
		BalanceChanges: []BalanceChange{
			{
				Token:     "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
				Standard:  "erc20",
				Amount:    big.NewInt(-2300000000),
				Direction: "outflow",
			},
			{
				Token:     "native",
				Standard:  "native",
				Amount:    big.NewInt(980000000000000000),
				Direction: "inflow",
			},
		},
	}

	netChanges := ComputeNetBalanceChanges([]SimulationResult{result0, result1}, signer)

	if len(netChanges) != 2 {
		t.Fatalf("expected 2 net changes, got %d", len(netChanges))
	}

	// Find USDC and native changes
	var usdcNet, nativeNet *BalanceChange
	for i := range netChanges {
		switch netChanges[i].Token {
		case "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48":
			usdcNet = &netChanges[i]
		case "native":
			nativeNet = &netChanges[i]
		}
	}

	if usdcNet == nil {
		t.Fatal("USDC net change not found")
	}
	if usdcNet.Direction != "outflow" {
		t.Errorf("expected USDC outflow, got %s", usdcNet.Direction)
	}
	if usdcNet.Amount.Cmp(big.NewInt(-2300000000)) != 0 {
		t.Errorf("expected USDC -2300000000, got %s", usdcNet.Amount.String())
	}

	if nativeNet == nil {
		t.Fatal("native net change not found")
	}
	if nativeNet.Direction != "inflow" {
		t.Errorf("expected native inflow, got %s", nativeNet.Direction)
	}
}

func TestComputeNetBalanceChanges_CancelsOut(t *testing.T) {
	// Two results that cancel each other out
	results := []SimulationResult{
		{
			BalanceChanges: []BalanceChange{
				{Token: "0xtoken", Amount: big.NewInt(-100)},
			},
		},
		{
			BalanceChanges: []BalanceChange{
				{Token: "0xtoken", Amount: big.NewInt(100)},
			},
		},
	}

	net := ComputeNetBalanceChanges(results, "")
	if len(net) != 0 {
		t.Errorf("expected 0 net changes when amounts cancel out, got %d", len(net))
	}
}
