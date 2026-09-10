package notify

import (
	"fmt"

	"github.com/ivanzzeth/remote-signer/internal/logger"
)

// ---------- the fan-out every notify client runs ----------
//
// Slack, Telegram, Pushover and webhook all answer the same question the same
// way: given a list of destinations and one message, send to each, tolerate the
// ones that fail, and report an error only when every destination failed.
// SendToChannels / SendToChats / SendToUsers / SendToURLs were four copies of
// that loop, differing in the noun in their strings and in almost nothing else.
//
// ⚠️ The partial-failure rule is the part that must not drift. "One of three
// channels failed" returns nil — the operator got told, just not everywhere —
// while "all three failed" returns an error, which is what escalation upstream
// keys on. A copy that flipped either half would either drop an alert nobody
// notices is missing, or fail an alert that was in fact delivered.
//
// Before this consolidation the four copies differed only in what they logged
// on the happy path: Telegram logged per recipient and again when all
// succeeded, webhook logged per recipient, Slack and Pushover logged nothing at
// all. There is one answer now, and it is Telegram's.

// fanOutTarget carries the words one client's fan-out uses. The strings are
// asserted by tests and read by operators, so each client keeps its own rather
// than having them generated from a single noun.
type fanOutTarget struct {
	// emptyErr is returned when the recipient list is empty
	// ("channel IDs are required").
	emptyErr string
	// allFailed prefixes the error returned when nothing was delivered
	// ("failed to send to any channel"); the last failure is wrapped into it.
	allFailed string
	// logField is the zerolog key for one recipient ("channel_id").
	logField string
	// sendFailed / partial / sent / allSent are the four log lines.
	sendFailed string
	partial    string
	sent       string
	allSent    string
	// mask rewrites a recipient before it is logged. nil logs it verbatim —
	// only Pushover user keys are secret enough to need this.
	mask func(string) string
}

// fanOut sends message to every recipient via send, and returns an error only
// if no recipient received it.
func fanOut(recipients []string, message string, t fanOutTarget, send func(recipient string) error) error {
	if len(recipients) == 0 {
		return fmt.Errorf("%s", t.emptyErr)
	}
	if message == "" {
		return fmt.Errorf("message is required")
	}

	log := logger.GetGlobal()
	var lastErr error
	successCount := 0

	for _, recipient := range recipients {
		shown := recipient
		if t.mask != nil {
			shown = t.mask(recipient)
		}
		if err := send(recipient); err != nil {
			lastErr = err
			log.Warn().
				Err(err).
				Str(t.logField, shown).
				Msg(t.sendFailed)
			continue
		}
		successCount++
		log.Debug().Str(t.logField, shown).Msg(t.sent)
	}

	if successCount == 0 {
		return fmt.Errorf("%s: %w", t.allFailed, lastErr)
	}

	if lastErr != nil {
		log.Warn().
			Int("success_count", successCount).
			Int("total_count", len(recipients)).
			Msg(t.partial)
	} else {
		log.Info().
			Int("recipient_count", len(recipients)).
			Msg(t.allSent)
	}

	return nil
}
