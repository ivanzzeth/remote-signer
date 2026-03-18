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

func TestDetectApproval_FromCalldata(t *testing.T) {
	// approve(address,uint256) selector
	if !DetectApproval(nil, "0x095ea7b3000000000000000000000000") {
		t.Error("expected approval detected from approve selector")
	}

	// setApprovalForAll(address,bool) selector
	if !DetectApproval(nil, "0xa22cb465000000000000000000000000") {
		t.Error("expected approval detected from setApprovalForAll selector")
	}

	// increaseAllowance(address,uint256) selector
	if !DetectApproval(nil, "0x39509351000000000000000000000000") {
		t.Error("expected approval detected from increaseAllowance selector")
	}

	// transfer selector - should not detect
	if DetectApproval(nil, "0xa9059cbb000000000000000000000000") {
		t.Error("did not expect approval for transfer selector")
	}
}

func TestDetectApproval_FromEvents(t *testing.T) {
	events := []SimEvent{
		{Event: "Transfer", Standard: "erc20"},
		{Event: "Approval", Standard: "erc20"},
	}
	if !DetectApproval(events, "0xa9059cbb") {
		t.Error("expected approval detected from Approval event")
	}

	events = []SimEvent{
		{Event: "Transfer", Standard: "erc20"},
	}
	if DetectApproval(events, "0xa9059cbb") {
		t.Error("did not expect approval when only Transfer event")
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
