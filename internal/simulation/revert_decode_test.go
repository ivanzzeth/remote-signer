package simulation

import (
	"context"
	"testing"
)

func TestDecodeRevertReason_ErrorString(t *testing.T) {
	// Error("hello") ABI-encoded
	data := "0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000568656c6c6f000000000000000000000000000000000000000000000000000000"
	got := decodeRevertReason(data)
	if got != "hello" {
		t.Fatalf("got %q want hello", got)
	}
}

func TestDecodeRevertReason_CustomSelector(t *testing.T) {
	reg := NewSignatureRegistry("", 0)
	reg.SeedFunction("0x5bf6f916", "TransactionDeadlinePassed()")
	got := ResolveRevert(context.Background(), reg, "0x5bf6f916")
	if got.Reason != "TransactionDeadlinePassed()" {
		t.Fatalf("got %q", got.Reason)
	}
	if got.Confidence != confidenceInferred {
		t.Fatalf("confidence %q", got.Confidence)
	}
}

func TestRevertDataFromCall_PrefersReturnData(t *testing.T) {
	got := revertDataFromCall("0x5bf6f916", "0xdeadbeef")
	if got != "0x5bf6f916" {
		t.Fatalf("got %q", got)
	}
}

func TestRevertDataFromCall_FallsBackToErrorData(t *testing.T) {
	got := revertDataFromCall("0x", "0x5bf6f916")
	if got != "0x5bf6f916" {
		t.Fatalf("got %q", got)
	}
}

func TestStrictDecodeEventLog_ERC20Transfer(t *testing.T) {
	log := TxLog{
		Address: "0xtoken",
		Topics: []string{
			transferTopic0,
			"0x0000000000000000000000001111111111111111111111111111111111111111",
			"0x0000000000000000000000002222222222222222222222222222222222222222",
		},
		Data: "0x0000000000000000000000000000000000000000000000000000000000000064",
	}
	args, ok := strictDecodeEventLog("Transfer(address,address,uint256)", log)
	if !ok {
		t.Fatal("expected decode ok")
	}
	if args["arg2"] != "100" {
		t.Fatalf("value %q", args["arg2"])
	}
}
