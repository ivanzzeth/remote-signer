package handler

import "testing"

func TestPresetMatchesQuery(t *testing.T) {
	item := PresetListItem{
		ID:          "evm/stargate",
		Name:        "Stargate",
		Description: "Aori-powered cross-chain bridge",
		TemplateIDs: []string{"evm/erc20", "evm/aori"},
		Enabled:     true,
	}

	cases := []struct {
		q    string
		want bool
	}{
		{"", true},
		{"stargate", true},
		{"STARGATE", true},
		{"aori", true},
		{"evm/erc20", true},
		{"bridge", true},
		{"uniswap", false},
	}
	for _, tc := range cases {
		got := presetMatchesQuery(item, tc.q)
		if got != tc.want {
			t.Errorf("presetMatchesQuery(%q) = %v, want %v", tc.q, got, tc.want)
		}
	}
}
