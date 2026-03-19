package simulation

import (
	"testing"
)

func TestParseEvents_ERC20Transfer(t *testing.T) {
	logs := []txLog{
		{
			Address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
			Topics: []string{
				transferTopic0,
				"0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
				"0x0000000000000000000000005e1f62dac767b0491e3ce72469c217365d5b48cc",
			},
			Data: "0x0000000000000000000000000000000000000000000000000000000089173700", // 2300000000
		},
	}

	events := ParseEvents(logs)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	e := events[0]
	if e.Event != "Transfer" {
		t.Errorf("expected Transfer, got %s", e.Event)
	}
	if e.Standard != "erc20" {
		t.Errorf("expected erc20, got %s", e.Standard)
	}
	if e.Args["from"] != "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266" {
		t.Errorf("unexpected from: %s", e.Args["from"])
	}
	if e.Args["to"] != "0x5e1f62dac767b0491e3ce72469c217365d5b48cc" {
		t.Errorf("unexpected to: %s", e.Args["to"])
	}
	if e.Args["value"] != "2300000000" {
		t.Errorf("expected value 2300000000, got %s", e.Args["value"])
	}
}

func TestParseEvents_ERC721Transfer(t *testing.T) {
	logs := []txLog{
		{
			Address: "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d",
			Topics: []string{
				transferTopic0,
				"0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
				"0x0000000000000000000000005e1f62dac767b0491e3ce72469c217365d5b48cc",
				"0x0000000000000000000000000000000000000000000000000000000000000064", // tokenId 100
			},
			Data: "0x",
		},
	}

	events := ParseEvents(logs)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	e := events[0]
	if e.Event != "Transfer" {
		t.Errorf("expected Transfer, got %s", e.Event)
	}
	if e.Standard != "erc721" {
		t.Errorf("expected erc721, got %s", e.Standard)
	}
	if e.Args["tokenId"] != "100" {
		t.Errorf("expected tokenId 100, got %s", e.Args["tokenId"])
	}
}

func TestParseEvents_ERC1155TransferSingle(t *testing.T) {
	logs := []txLog{
		{
			Address: "0x1234567890abcdef1234567890abcdef12345678",
			Topics: []string{
				transferSingleTopic0,
				"0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // operator
				"0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266", // from
				"0x0000000000000000000000005e1f62dac767b0491e3ce72469c217365d5b48cc", // to
			},
			// id=1, value=50
			Data: "0x00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000032",
		},
	}

	events := ParseEvents(logs)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	e := events[0]
	if e.Event != "TransferSingle" {
		t.Errorf("expected TransferSingle, got %s", e.Event)
	}
	if e.Standard != "erc1155" {
		t.Errorf("expected erc1155, got %s", e.Standard)
	}
	if e.Args["id"] != "1" {
		t.Errorf("expected id 1, got %s", e.Args["id"])
	}
	if e.Args["value"] != "50" {
		t.Errorf("expected value 50, got %s", e.Args["value"])
	}
}

func TestParseEvents_WETHDeposit(t *testing.T) {
	logs := []txLog{
		{
			Address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
			Topics: []string{
				depositTopic0,
				"0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			},
			Data: "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000", // 1 ETH
		},
	}

	events := ParseEvents(logs)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	e := events[0]
	if e.Event != "Deposit" {
		t.Errorf("expected Deposit, got %s", e.Event)
	}
	if e.Standard != "weth" {
		t.Errorf("expected weth, got %s", e.Standard)
	}
	if e.Args["wad"] != "1000000000000000000" {
		t.Errorf("expected wad 1000000000000000000, got %s", e.Args["wad"])
	}
}

func TestParseEvents_WETHWithdrawal(t *testing.T) {
	logs := []txLog{
		{
			Address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
			Topics: []string{
				withdrawalTopic0,
				"0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			},
			Data: "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
		},
	}

	events := ParseEvents(logs)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Event != "Withdrawal" {
		t.Errorf("expected Withdrawal, got %s", events[0].Event)
	}
	if events[0].Standard != "weth" {
		t.Errorf("expected weth, got %s", events[0].Standard)
	}
}

func TestParseEvents_Approval(t *testing.T) {
	logs := []txLog{
		{
			Address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
			Topics: []string{
				approvalTopic0,
				"0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
				"0x0000000000000000000000005e1f62dac767b0491e3ce72469c217365d5b48cc",
			},
			Data: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		},
	}

	events := ParseEvents(logs)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Event != "Approval" {
		t.Errorf("expected Approval, got %s", events[0].Event)
	}
	if events[0].Standard != "erc20" {
		t.Errorf("expected erc20, got %s", events[0].Standard)
	}
}

func TestParseEvents_ApprovalForAll(t *testing.T) {
	logs := []txLog{
		{
			Address: "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d",
			Topics: []string{
				approvalForAllTopic0,
				"0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
				"0x0000000000000000000000005e1f62dac767b0491e3ce72469c217365d5b48cc",
			},
			Data: "0x",
		},
	}

	events := ParseEvents(logs)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Event != "ApprovalForAll" {
		t.Errorf("expected ApprovalForAll, got %s", events[0].Event)
	}
}

func TestDetectApproval_NonZeroValue(t *testing.T) {
	// Approval with non-zero value → detected
	events := []SimEvent{
		{Event: "Approval", Standard: "erc20", Args: map[string]string{"owner": "0xabc", "value": "1000000"}},
	}
	if !DetectApproval(events, nil) {
		t.Error("expected approval detected for non-zero value")
	}

	// ApprovalForAll (no value field, but Event matches) → needs non-empty value to detect
	events = []SimEvent{
		{Event: "ApprovalForAll", Standard: "erc721", Args: map[string]string{"owner": "0xabc", "value": "1"}},
	}
	if !DetectApproval(events, nil) {
		t.Error("expected ApprovalForAll detected")
	}
}

func TestDetectApproval_ZeroValueSkipped(t *testing.T) {
	// Approval with value=0 (transferFrom side effect) → NOT detected
	events := []SimEvent{
		{Event: "Approval", Standard: "erc20", Args: map[string]string{"owner": "0xabc", "value": "0"}},
	}
	if DetectApproval(events, nil) {
		t.Error("did not expect approval for value=0 (transferFrom side effect)")
	}
}

func TestDetectApproval_NoEvents(t *testing.T) {
	if DetectApproval(nil, nil) {
		t.Error("did not expect approval for nil events")
	}
	if DetectApproval([]SimEvent{{Event: "Transfer"}}, nil) {
		t.Error("did not expect approval for Transfer-only events")
	}
}

func TestDetectApproval_ManagedSignerFilter(t *testing.T) {
	managed := map[string]bool{"0xabc": true}
	// Managed signer approval → detected
	events := []SimEvent{
		{Event: "Approval", Args: map[string]string{"owner": "0xabc", "value": "100"}},
	}
	if !DetectApproval(events, managed) {
		t.Error("expected approval for managed signer")
	}
	// Non-managed signer approval → NOT detected
	events = []SimEvent{
		{Event: "Approval", Args: map[string]string{"owner": "0xunknown", "value": "100"}},
	}
	if DetectApproval(events, managed) {
		t.Error("did not expect approval for non-managed signer")
	}
}

func TestDetectDangerousStateChanges_OwnershipTransferred(t *testing.T) {
	managed := map[string]bool{"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266": true}

	// Managed signer losing ownership → detected
	logs := []txLog{{
		Topics: []string{
			"0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",
			"0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266", // previousOwner (managed)
			"0x0000000000000000000000001234567890abcdef1234567890abcdef12345678", // newOwner
		},
	}}
	reason := DetectDangerousStateChanges(logs, managed)
	if reason == "" {
		t.Error("expected OwnershipTransferred to be detected for managed signer")
	}

	// Non-managed signer losing ownership → NOT detected
	logs2 := []txLog{{
		Topics: []string{
			"0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",
			"0x0000000000000000000000001111111111111111111111111111111111111111", // not managed
			"0x0000000000000000000000002222222222222222222222222222222222222222",
		},
	}}
	reason2 := DetectDangerousStateChanges(logs2, managed)
	if reason2 != "" {
		t.Errorf("did not expect detection for non-managed signer, got: %s", reason2)
	}
}

func TestDetectDangerousStateChanges_ApprovalForAll(t *testing.T) {
	managed := map[string]bool{"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266": true}

	// ApprovalForAll(true) for managed signer → detected
	logs := []txLog{{
		Topics: []string{
			"0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31",
			"0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266", // owner (managed)
			"0x0000000000000000000000001234567890abcdef1234567890abcdef12345678", // operator
		},
		Data: "0x0000000000000000000000000000000000000000000000000000000000000001", // approved=true
	}}
	reason := DetectDangerousStateChanges(logs, managed)
	if reason == "" {
		t.Error("expected ApprovalForAll(true) to be detected for managed signer")
	}

	// ApprovalForAll(false) = revoke → NOT detected
	logs2 := []txLog{{
		Topics: []string{
			"0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31",
			"0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			"0x0000000000000000000000001234567890abcdef1234567890abcdef12345678",
		},
		Data: "0x0000000000000000000000000000000000000000000000000000000000000000", // approved=false
	}}
	reason2 := DetectDangerousStateChanges(logs2, managed)
	if reason2 != "" {
		t.Errorf("did not expect detection for ApprovalForAll(false), got: %s", reason2)
	}
}

func TestDetectDangerousStateChanges_Upgraded(t *testing.T) {
	// Any Upgraded event → detected (regardless of managed signers)
	logs := []txLog{{
		Topics: []string{
			"0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",
			"0x0000000000000000000000001234567890abcdef1234567890abcdef12345678", // new implementation
		},
	}}
	reason := DetectDangerousStateChanges(logs, nil)
	if reason == "" {
		t.Error("expected Upgraded event to be detected")
	}
}

func TestDetectDangerousStateChanges_AdminChanged(t *testing.T) {
	// Any AdminChanged event → detected
	logs := []txLog{{
		Topics: []string{
			"0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f",
		},
		Data: "0x0000000000000000000000001111111111111111111111111111111111111111" +
			"0000000000000000000000002222222222222222222222222222222222222222",
	}}
	reason := DetectDangerousStateChanges(logs, nil)
	if reason == "" {
		t.Error("expected AdminChanged event to be detected")
	}
}

func TestDetectDangerousStateChanges_SafeEvents(t *testing.T) {
	managed := map[string]bool{"0xabc": true}

	// Transfer event → NOT dangerous
	logs := []txLog{{
		Topics: []string{
			"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
			"0x000000000000000000000000abc0000000000000000000000000000000000000",
			"0x000000000000000000000000def0000000000000000000000000000000000000",
		},
	}}
	reason := DetectDangerousStateChanges(logs, managed)
	if reason != "" {
		t.Errorf("Transfer event should not be dangerous, got: %s", reason)
	}

	// Empty logs → safe
	if DetectDangerousStateChanges(nil, managed) != "" {
		t.Error("nil logs should be safe")
	}
}

func TestParseEvents_EmptyLogs(t *testing.T) {
	events := ParseEvents(nil)
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}

	events = ParseEvents([]txLog{})
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}

func TestParseEvents_UnknownTopic(t *testing.T) {
	logs := []txLog{
		{
			Address: "0x1234567890abcdef1234567890abcdef12345678",
			Topics:  []string{"0xdeadbeef00000000000000000000000000000000000000000000000000000000"},
			Data:    "0x",
		},
	}

	events := ParseEvents(logs)
	if len(events) != 0 {
		t.Errorf("expected 0 events for unknown topic, got %d", len(events))
	}
}

func TestTopicToAddress(t *testing.T) {
	addr := topicToAddress("0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266")
	if addr != "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266" {
		t.Errorf("unexpected address: %s", addr)
	}
}

func TestTopicToUint256(t *testing.T) {
	val := topicToUint256("0x0000000000000000000000000000000000000000000000000000000000000064")
	if val != "100" {
		t.Errorf("expected 100, got %s", val)
	}
}

func TestDataToHexValue(t *testing.T) {
	data := "0x0000000000000000000000000000000000000000000000000000000089173700"
	val := dataToHexValue(data, 0)
	if val != "2300000000" {
		t.Errorf("expected 2300000000, got %s", val)
	}
}

func TestTrimHexPrefix(t *testing.T) {
	if trimHexPrefix("0xabcd") != "abcd" {
		t.Error("failed to trim 0x prefix")
	}
	if trimHexPrefix("0Xabcd") != "abcd" {
		t.Error("failed to trim 0X prefix")
	}
	if trimHexPrefix("abcd") != "abcd" {
		t.Error("should not modify string without 0x prefix")
	}
}
