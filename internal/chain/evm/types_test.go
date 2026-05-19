package evm

import (
	"encoding/json"
	"testing"
)

func TestTypedDataDomain_UnmarshalChainId(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"number", `{"chainId": 1}`, "1"},
		{"large number", `{"chainId": 31337}`, "31337"},
		{"string", `{"chainId": "1"}`, "1"},
		{"decimal-as-string", `{"chainId": "31337"}`, "31337"},
		{"missing", `{}`, ""},
		{"explicit null", `{"chainId": null}`, ""},
		{"with other fields", `{"name": "T", "chainId": 137, "version": "1"}`, "137"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var d TypedDataDomain
			if err := json.Unmarshal([]byte(tc.in), &d); err != nil {
				t.Fatalf("unmarshal %q: %v", tc.in, err)
			}
			if d.ChainId != tc.want {
				t.Fatalf("chainId: got %q want %q", d.ChainId, tc.want)
			}
		})
	}
}

func TestTypedDataDomain_OtherFieldsPreserved(t *testing.T) {
	in := []byte(`{
		"name": "Test Token",
		"version": "1",
		"chainId": 31337,
		"verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
		"salt": "0xabc"
	}`)
	var d TypedDataDomain
	if err := json.Unmarshal(in, &d); err != nil {
		t.Fatal(err)
	}
	if d.Name != "Test Token" || d.Version != "1" ||
		d.ChainId != "31337" ||
		d.VerifyingContract != "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC" ||
		d.Salt != "0xabc" {
		t.Fatalf("unexpected: %+v", d)
	}
}
