package types

import "testing"

// DeriveApprovalSource is what powers the UI's "approved by ..." line
// for sign requests persisted before ApprovalSource existed. Each
// branch must remain stable: changing the precedence here would
// silently re-label historic rows.
func TestDeriveApprovalSource(t *testing.T) {
	admin := "admin-key"
	ruleID := "rule_001"

	cases := []struct {
		name      string
		rule      *string
		approver  *string
		want      string
	}{
		{name: "manual_wins_over_rule", rule: &ruleID, approver: &admin, want: ApprovalSourceManual},
		{name: "manual_no_rule", rule: nil, approver: &admin, want: ApprovalSourceManual},
		{name: "rule_match", rule: &ruleID, approver: nil, want: ApprovalSourceRule},
		{name: "neither_falls_to_simulation", rule: nil, approver: nil, want: ApprovalSourceSimulation},
		{name: "empty_strings_count_as_nil", rule: strp(""), approver: strp(""), want: ApprovalSourceSimulation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveApprovalSource(tc.rule, tc.approver)
			if got != tc.want {
				t.Errorf("DeriveApprovalSource(%v, %v) = %q, want %q", tc.rule, tc.approver, got, tc.want)
			}
		})
	}
}

func strp(s string) *string { return &s }
