package evm

import (
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Sandbox acceptance tests per js-rules-v5.md §11.7. CI mandatory.

func TestSandbox_InfiniteLoop_RejectTimeout(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	script := `function validate(i){ for(;;){} return { valid: true }; }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)

	assert.False(t, res.Valid, "infinite loop must be rejected")
	assert.True(t, strings.Contains(res.Reason, "timeout") || strings.Contains(res.Reason, "Interrupt") || strings.Contains(res.Reason, "script_error"), "reason should indicate timeout/reject, got %q", res.Reason)
}

func TestSandbox_HugeAlloc_RejectOrTimeout(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	// Try to allocate very large array; should hit timeout or reject, no panic
	script := `function validate(i){ var a = []; for(var j=0;j<5e6;j++) a.push(1); return { valid: true }; }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)

	// Either timeout or valid; must not panic. Spec: reject <200ms, memory ≤50MB.
	assert.False(t, res.Valid, "huge alloc should be rejected or timeout")
	assert.True(t, res.Reason != "", "should have a reason")
}

func TestSandbox_PrototypePollution_NextRuleNoSee(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}

	// First rule: pollute Object.prototype
	script1 := `function validate(i){ if (typeof Object.prototype !== 'undefined') { Object.prototype.__polluted = 1; } return { valid: true }; }`
	res1 := e.wrappedValidate(script1, input, nil)
	require.True(t, res1.Valid, "first script should run: %s", res1.Reason)

	// Second rule: must not see pollution (fresh VM)
	script2 := `function validate(i){ return { valid: (typeof Object.prototype === 'undefined' || Object.prototype.__polluted === undefined) }; }`
	res2 := e.wrappedValidate(script2, input, nil)
	assert.True(t, res2.Valid, "second rule must not see prototype pollution; reason=%s", res2.Reason)
}

func TestSandbox_PollutionAndSecondRule_IsolationNoCrash(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}

	script1 := `function validate(i){ try { this.foo = 1; } catch(e){} return { valid: true }; }`
	res1 := e.wrappedValidate(script1, input, nil)
	require.True(t, res1.Valid, "first: %s", res1.Reason)

	script2 := `function validate(i){ return { valid: true }; }`
	res2 := e.wrappedValidate(script2, input, nil)
	assert.True(t, res2.Valid, "second rule must run without crash: %s", res2.Reason)
}

func TestSandbox_GlobalPollution_SecondRuleNoSeeMutation(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}

	// First: mutate a global name if possible (after removeGlobals, many are undefined)
	script1 := `function validate(i){ try { if (typeof globalThis !== 'undefined') globalThis.__sandbox_test = 1; } catch(e){} return { valid: true }; }`
	res1 := e.wrappedValidate(script1, input, nil)
	require.True(t, res1.Valid, "first: %s", res1.Reason)

	// Second: must not see __sandbox_test (fresh VM)
	script2 := `function validate(i){ var ok = (typeof globalThis === 'undefined' || globalThis.__sandbox_test === undefined); return { valid: ok }; }`
	res2 := e.wrappedValidate(script2, input, nil)
	assert.True(t, res2.Valid, "second rule must not see global mutation: %s", res2.Reason)
}

func TestSandbox_NewFunction_Reject(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	script := `function validate(i){ var F = Function; return { valid: (typeof F === 'undefined') }; }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)

	// Function is removed; script may reference it and get undefined, so valid could be true, or it might throw
	assert.True(t, res.Valid || (!res.Valid && res.Reason != ""), "must not allow Function: valid=%v reason=%s", res.Valid, res.Reason)
	if !res.Valid {
		assert.True(t, strings.Contains(res.Reason, "Function") || strings.Contains(res.Reason, "script_error") || strings.Contains(res.Reason, "undefined"), "reason should reflect Function reject: %s", res.Reason)
	}
}

func TestSandbox_DateAbuse_RejectOrNoHang(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	// Date is removed; script that tries to spin on Date should not hang (Date is undefined, so throws or no-op)
	script := `function validate(i){ var d = Date; if (typeof d !== 'undefined') { while(1) new Date(); } return { valid: true }; }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)

	assert.True(t, res.Valid || (!res.Valid && res.Reason != ""), "must not hang: valid=%v reason=%s", res.Valid, res.Reason)
}

func TestSandbox_InvalidReturn_RejectInvalidShape(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}

	tests := []struct {
		name   string
		script string
	}{
		{"return number", `function validate(i){ return 42; }`},
		{"return string", `function validate(i){ return "ok"; }`},
		{"return object without valid", `function validate(i){ return { reason: "x" }; }`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := e.wrappedValidate(tt.script, input, nil)
			assert.False(t, res.Valid, "invalid return shape must be rejected")
			assert.True(t, res.Reason != "", "should have a rejection reason")
		})
	}
}

func TestSandbox_OOMLike_RejectNoPanic(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	// Script that does something allocation-heavy; must reject or timeout, never panic
	script := `function validate(i){ var x = []; for(var i=0;i<1e7;i++) x.push({a:i}); return { valid: true }; }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)

	assert.False(t, res.Valid, "OOM-like script should be rejected or timeout")
	assert.True(t, res.Reason != "", "should have reason")
}
