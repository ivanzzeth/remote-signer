package evm

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

func TestAbiDecodeTransferFromPayload(t *testing.T) {
	// transferFrom(from, to, amount): 3 x 32 bytes = 96 bytes. Each address is 24 zero hex + 40 address hex.
	from := "000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266" // 64
	to := "0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc4"   // 64
	amount := "0000000000000000000000000000000000000000000000000000000000000000" // 64
	raw := from + to + amount
	data, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 96 {
		t.Fatalf("expected 96 bytes, got %d (raw len=%d)", len(data), len(raw))
	}
	typ1, _ := abi.NewType("address", "", nil)
	typ2, _ := abi.NewType("address", "", nil)
	typ3, _ := abi.NewType("uint256", "", nil)
	args := abi.Arguments{
		{Type: typ1},
		{Type: typ2},
		{Type: typ3},
	}
	unpacked, err := args.UnpackValues(data)
	if err != nil {
		t.Fatalf("UnpackValues: %v", err)
	}
	if len(unpacked) != 3 {
		t.Fatalf("expected 3 values, got %d", len(unpacked))
	}
}
