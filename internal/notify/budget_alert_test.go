package notify

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ---------- NewBudgetAlertNotifier ----------

func TestNewBudgetAlertNotifier(t *testing.T) {
	n := NewBudgetAlertNotifier(nil, nil)
	require.NotNil(t, n)
	assert.Equal(t, 1, n.priority, "default priority should be 1 (high)")
	assert.Equal(t, "persistent", n.sound, "default sound should be 'persistent'")
	assert.Nil(t, n.notifyService)
	assert.Nil(t, n.channels)
}

// ---------- SendBudgetAlert — nil guards ----------

func TestBudgetAlertNotifier_NilService(t *testing.T) {
	ch := &Channel{Pushover: []string{"user1"}}
	n := NewBudgetAlertNotifier(nil, ch)

	err := n.SendBudgetAlert(context.Background(), types.RuleID("r1"), "count", "80", "100", 80, 80)
	assert.NoError(t, err, "nil notifyService should return nil without error")
}

func TestBudgetAlertNotifier_NilChannel(t *testing.T) {
	// NotifyService requires a config; we don't actually need a real one here
	// because the nil-channel guard returns before calling any service method.
	// We can pass a non-nil notifyService with an empty struct to test the guard.
	svc := &NotifyService{} // zero-value, not started — that's fine for this test
	n := NewBudgetAlertNotifier(svc, nil)

	err := n.SendBudgetAlert(context.Background(), types.RuleID("r1"), "count", "80", "100", 80, 80)
	assert.NoError(t, err, "nil channels should return nil without error")
}

// ---------- SendBudgetAlert — message format ----------

func TestBudgetAlertNotifier_MessageFormat(t *testing.T) {
	// We create a real NotifyService with a buffered channel so SendWithPriority
	// drops the message into the internal buffer without needing a consumer goroutine.
	svc := &NotifyService{
		msgChan: make(chan notifyMessage, 10),
	}
	ch := &Channel{Pushover: []string{"user1"}}
	n := NewBudgetAlertNotifier(svc, ch)

	ruleID := types.RuleID("rule-42")
	unit := "usdt"
	spent := "8000"
	maxTotal := "10000"
	var pct int64 = 80
	alertPct := 75

	err := n.SendBudgetAlert(context.Background(), ruleID, unit, spent, maxTotal, pct, alertPct)
	require.NoError(t, err)

	// Drain the internal message channel to inspect the formatted message.
	select {
	case msg := <-svc.msgChan:
		assert.Contains(t, msg.message, string(ruleID), "message should contain rule_id")
		assert.Contains(t, msg.message, unit, "message should contain unit")
		assert.Contains(t, msg.message, spent, "message should contain spent amount")
		assert.Contains(t, msg.message, maxTotal, "message should contain max total")
		assert.Contains(t, msg.message, "80%", "message should contain pct")
		assert.Contains(t, msg.message, "75%", "message should contain alertPct")
		assert.Equal(t, 1, msg.priority, "priority should be high (1)")
		assert.Equal(t, "persistent", msg.sound)
	default:
		t.Fatal("expected a message in the internal channel but got none")
	}
}
