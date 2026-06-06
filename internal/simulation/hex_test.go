package simulation

import "testing"

func TestNormalizeRPCQuantity(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", "0x0"},
		{"0", "0x0"},
		{"0x0", "0x0"},
		{"1000000", "0xf4240"},
		{"0xf4240", "0xf4240"},
		{"178678", "0x2b9f6"},
	}
	for _, tc := range tests {
		if got := normalizeRPCQuantity(tc.in); got != tc.want {
			t.Fatalf("normalizeRPCQuantity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeRPCGasOptional(t *testing.T) {
	if got := normalizeRPCGasOptional(""); got != "" {
		t.Fatalf("empty gas: got %q", got)
	}
	if got := normalizeRPCGasOptional("178678"); got != "0x2b9f6" {
		t.Fatalf("decimal gas: got %q", got)
	}
}
