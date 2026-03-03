package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// NewNotifyService
// ============================================================

func TestNewNotifyService_NilConfig(t *testing.T) {
	_, err := NewNotifyService(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config is required")
}

func TestNewNotifyService_EmptyConfig(t *testing.T) {
	svc, err := NewNotifyService(&Config{})
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Nil(t, svc.slackClient, "slack client should be nil when not configured")
	assert.Nil(t, svc.pushoverClient, "pushover client should be nil when not configured")
	assert.Nil(t, svc.webhookClient, "webhook client should be nil when not configured")
	assert.Nil(t, svc.telegramClient, "telegram client should be nil when not configured")
	assert.NotNil(t, svc.msgChan, "internal message channel should be initialized")
}

func TestNewNotifyService_SlackDisabled(t *testing.T) {
	svc, err := NewNotifyService(&Config{
		Slack: &SlackConfig{Enabled: false, BotToken: ""},
	})
	require.NoError(t, err)
	assert.Nil(t, svc.slackClient, "slack client should be nil when disabled")
}

func TestNewNotifyService_SlackEnabled_MissingToken(t *testing.T) {
	_, err := NewNotifyService(&Config{
		Slack: &SlackConfig{Enabled: true, BotToken: ""},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "slack bot token is required when enabled")
}

func TestNewNotifyService_SlackEnabled_Valid(t *testing.T) {
	svc, err := NewNotifyService(&Config{
		Slack: &SlackConfig{Enabled: true, BotToken: "xoxb-test"},
	})
	require.NoError(t, err)
	assert.NotNil(t, svc.slackClient)
}

func TestNewNotifyService_PushoverDisabled(t *testing.T) {
	svc, err := NewNotifyService(&Config{
		Pushover: &PushoverConfig{Enabled: false},
	})
	require.NoError(t, err)
	assert.Nil(t, svc.pushoverClient, "pushover client should be nil when disabled")
}

func TestNewNotifyService_PushoverEnabled_MissingToken(t *testing.T) {
	_, err := NewNotifyService(&Config{
		Pushover: &PushoverConfig{Enabled: true, AppToken: ""},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pushover app token is required when enabled")
}

func TestNewNotifyService_PushoverEnabled_Valid(t *testing.T) {
	svc, err := NewNotifyService(&Config{
		Pushover: &PushoverConfig{
			Enabled:  true,
			AppToken: "app-tok",
		},
	})
	require.NoError(t, err)
	assert.NotNil(t, svc.pushoverClient)
}

func TestNewNotifyService_PushoverDefaults(t *testing.T) {
	svc, err := NewNotifyService(&Config{
		Pushover: &PushoverConfig{
			Enabled:  true,
			AppToken: "app-tok",
			// Leave Retry, Expire, MaxRetries, RetryDelay at 0 to trigger defaults
		},
	})
	require.NoError(t, err)
	require.NotNil(t, svc.pushoverClient)
	assert.Equal(t, 30, svc.pushoverClient.retry, "default retry should be 30")
	assert.Equal(t, 300, svc.pushoverClient.expire, "default expire should be 300")
	assert.Equal(t, 3, svc.pushoverClient.maxRetries, "default maxRetries should be 3")
	assert.Equal(t, 1*time.Second, svc.pushoverClient.retryDelay, "default retryDelay should be 1s")
}

func TestNewNotifyService_PushoverCustomValues(t *testing.T) {
	svc, err := NewNotifyService(&Config{
		Pushover: &PushoverConfig{
			Enabled:    true,
			AppToken:   "app-tok",
			Retry:      60,
			Expire:     600,
			MaxRetries: 5,
			RetryDelay: 2,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, svc.pushoverClient)
	assert.Equal(t, 60, svc.pushoverClient.retry)
	assert.Equal(t, 600, svc.pushoverClient.expire)
	assert.Equal(t, 5, svc.pushoverClient.maxRetries)
	assert.Equal(t, 2*time.Second, svc.pushoverClient.retryDelay)
}

func TestNewNotifyService_WebhookDisabled(t *testing.T) {
	svc, err := NewNotifyService(&Config{
		Webhook: &WebhookConfig{Enabled: false},
	})
	require.NoError(t, err)
	assert.Nil(t, svc.webhookClient, "webhook client should be nil when disabled")
}

func TestNewNotifyService_WebhookEnabled_DefaultTimeout(t *testing.T) {
	svc, err := NewNotifyService(&Config{
		Webhook: &WebhookConfig{Enabled: true},
	})
	require.NoError(t, err)
	assert.NotNil(t, svc.webhookClient)
}

func TestNewNotifyService_WebhookEnabled_CustomTimeout(t *testing.T) {
	svc, err := NewNotifyService(&Config{
		Webhook: &WebhookConfig{Enabled: true, Timeout: 30 * time.Second},
	})
	require.NoError(t, err)
	assert.NotNil(t, svc.webhookClient)
}

func TestNewNotifyService_TelegramDisabled(t *testing.T) {
	svc, err := NewNotifyService(&Config{
		Telegram: &TelegramConfig{Enabled: false, BotToken: ""},
	})
	require.NoError(t, err)
	assert.Nil(t, svc.telegramClient, "telegram client should be nil when disabled")
}

func TestNewNotifyService_TelegramEnabled_MissingToken(t *testing.T) {
	_, err := NewNotifyService(&Config{
		Telegram: &TelegramConfig{Enabled: true, BotToken: ""},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "telegram bot token is required when enabled")
}

func TestNewNotifyService_TelegramEnabled_Valid(t *testing.T) {
	svc, err := NewNotifyService(&Config{
		Telegram: &TelegramConfig{Enabled: true, BotToken: "123:ABC"},
	})
	require.NoError(t, err)
	assert.NotNil(t, svc.telegramClient)
}

func TestNewNotifyService_AllEnabled(t *testing.T) {
	svc, err := NewNotifyService(&Config{
		Slack:    &SlackConfig{Enabled: true, BotToken: "xoxb-test"},
		Pushover: &PushoverConfig{Enabled: true, AppToken: "app-tok"},
		Webhook:  &WebhookConfig{Enabled: true},
		Telegram: &TelegramConfig{Enabled: true, BotToken: "123:ABC"},
	})
	require.NoError(t, err)
	assert.NotNil(t, svc.slackClient)
	assert.NotNil(t, svc.pushoverClient)
	assert.NotNil(t, svc.webhookClient)
	assert.NotNil(t, svc.telegramClient)
}

// ============================================================
// Send — validation and channel-full
// ============================================================

func TestSend_NilChannel(t *testing.T) {
	svc := newTestService(t)
	err := svc.Send(nil, "hello")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "channel is required")
}

func TestSend_EmptyMessage(t *testing.T) {
	svc := newTestService(t)
	err := svc.Send(&Channel{Slack: []string{"C1"}}, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "message is required")
}

func TestSend_Success(t *testing.T) {
	svc := newTestService(t)
	ch := &Channel{Slack: []string{"C1"}}
	err := svc.Send(ch, "hello")
	require.NoError(t, err)

	// Verify the message was placed in the channel
	select {
	case msg := <-svc.msgChan:
		assert.Equal(t, "hello", msg.message)
		assert.Equal(t, ch, msg.channel)
		assert.Equal(t, 0, msg.priority)
		assert.Equal(t, "", msg.sound)
	default:
		t.Fatal("expected message in internal channel")
	}
}

func TestSend_ChannelFull(t *testing.T) {
	// Create a service with a zero-capacity channel to force the "full" path
	svc := &NotifyService{
		logger:  logger.GetGlobal(),
		msgChan: make(chan notifyMessage), // unbuffered, no consumer => full
	}
	ch := &Channel{Slack: []string{"C1"}}
	err := svc.Send(ch, "overflow")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "notification channel full")
}

// ============================================================
// SendWithPriority — validation and channel-full
// ============================================================

func TestSendWithPriority_NilChannel(t *testing.T) {
	svc := newTestService(t)
	err := svc.SendWithPriority(nil, "hello", 2, "persistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "channel is required")
}

func TestSendWithPriority_EmptyMessage(t *testing.T) {
	svc := newTestService(t)
	err := svc.SendWithPriority(&Channel{Slack: []string{"C1"}}, "", 2, "persistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "message is required")
}

func TestSendWithPriority_Success(t *testing.T) {
	svc := newTestService(t)
	ch := &Channel{Pushover: []string{"user1"}}
	err := svc.SendWithPriority(ch, "alert!", 2, "siren")
	require.NoError(t, err)

	select {
	case msg := <-svc.msgChan:
		assert.Equal(t, "alert!", msg.message)
		assert.Equal(t, 2, msg.priority)
		assert.Equal(t, "siren", msg.sound)
	default:
		t.Fatal("expected message in internal channel")
	}
}

func TestSendWithPriority_ChannelFull(t *testing.T) {
	svc := &NotifyService{
		logger:  logger.GetGlobal(),
		msgChan: make(chan notifyMessage),
	}
	ch := &Channel{Slack: []string{"C1"}}
	err := svc.SendWithPriority(ch, "overflow", 1, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "notification channel full")
}

// ============================================================
// Start / Stop / consumeLoop — lifecycle tests
// ============================================================

func TestStartStop_NoMessages(t *testing.T) {
	svc := newTestService(t)
	svc.Start(context.Background())
	// Immediately stop — should not hang
	svc.Stop()
}

func TestStop_NilCancel(t *testing.T) {
	// Stop on a service that was never started should not panic
	svc := newTestService(t)
	svc.Stop() // cancel is nil, should be safe
}

func TestStartStop_ConsumesMessages(t *testing.T) {
	// Set up a webhook server that records calls
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := newTestServiceWithWebhook(t, srv.URL)
	svc.Start(context.Background())

	ch := &Channel{Webhook: []string{srv.URL}}
	err := svc.Send(ch, "test message")
	require.NoError(t, err)

	// Give the consumer loop time to process
	assert.Eventually(t, func() bool {
		return callCount.Load() >= 1
	}, 2*time.Second, 10*time.Millisecond, "message should be consumed and sent")

	svc.Stop()
}

func TestConsumeLoop_DrainsOnCancel(t *testing.T) {
	// Verify that remaining messages are drained when the context is cancelled.
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := newTestServiceWithWebhook(t, srv.URL)
	ch := &Channel{Webhook: []string{srv.URL}}

	// Put messages in BEFORE starting, so they sit in the buffer
	for i := 0; i < 5; i++ {
		err := svc.Send(ch, "drain-test")
		require.NoError(t, err)
	}

	svc.Start(context.Background())
	// Stop immediately — the consumeLoop should drain the remaining messages
	svc.Stop()

	assert.Equal(t, int32(5), callCount.Load(), "all 5 buffered messages should be drained on stop")
}

func TestConsumeLoop_MultipleMessages(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := newTestServiceWithWebhook(t, srv.URL)
	svc.Start(context.Background())

	ch := &Channel{Webhook: []string{srv.URL}}
	for i := 0; i < 10; i++ {
		err := svc.Send(ch, "msg")
		require.NoError(t, err)
	}

	assert.Eventually(t, func() bool {
		return callCount.Load() >= 10
	}, 3*time.Second, 10*time.Millisecond, "all 10 messages should be processed")

	svc.Stop()
}

// ============================================================
// sendSync — branch coverage
// ============================================================

func TestSendSync_NilChannel(t *testing.T) {
	svc := newTestService(t)
	// Should not panic
	svc.sendSync(nil, "msg", 0, "")
}

func TestSendSync_EmptyMessage(t *testing.T) {
	svc := newTestService(t)
	// Should not panic
	svc.sendSync(&Channel{Slack: []string{"C1"}}, "", 0, "")
}

func TestSendSync_SlackNotConfigured(t *testing.T) {
	// slackClient is nil — should log warning but not panic
	svc := newTestService(t)
	svc.sendSync(&Channel{Slack: []string{"C1"}}, "msg", 0, "")
}

func TestSendSync_PushoverNotConfigured(t *testing.T) {
	// pushoverClient is nil — should log warning but not panic
	svc := newTestService(t)
	svc.sendSync(&Channel{Pushover: []string{"user1"}}, "msg", 0, "")
}

func TestSendSync_WebhookNotConfigured(t *testing.T) {
	// webhookClient is nil — should log warning but not panic
	svc := newTestService(t)
	svc.sendSync(&Channel{Webhook: []string{"http://example.com"}}, "msg", 0, "")
}

func TestSendSync_SlackSuccess(t *testing.T) {
	var received map[string]interface{}
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		_ = json.NewDecoder(req.Body).Decode(&received)
		return newJSONResponse(200, map[string]interface{}{"ok": true}), nil
	})

	svc := newTestService(t)
	svc.slackClient = slackClientWithRT(rt)

	svc.sendSync(&Channel{Slack: []string{"C123"}}, "hello slack", 0, "")
	assert.Equal(t, "hello slack", received["text"])
}

func TestSendSync_SlackFailure(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newJSONResponse(200, map[string]interface{}{
			"ok":    false,
			"error": "channel_not_found",
		}), nil
	})

	svc := newTestService(t)
	svc.slackClient = slackClientWithRT(rt)

	// Should not panic; failure is logged
	svc.sendSync(&Channel{Slack: []string{"C-bad"}}, "msg", 0, "")
}

func TestSendSync_PushoverSuccess(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newJSONResponse(200, PushoverResponse{Status: 1, Request: "ok"}), nil
	})

	svc := newTestService(t)
	svc.pushoverClient = newPushoverClientWithRT(rt)

	svc.sendSync(&Channel{Pushover: []string{"user1"}}, "hello pushover", 1, "siren")
}

func TestSendSync_PushoverFailure(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newJSONResponse(200, PushoverResponse{Status: 0, Errors: []string{"bad token"}}), nil
	})

	svc := newTestService(t)
	svc.pushoverClient = newPushoverClientWithRT(rt)

	// Should not panic; failure is logged
	svc.sendSync(&Channel{Pushover: []string{"user1"}}, "msg", 0, "")
}

func TestSendSync_WebhookSuccess(t *testing.T) {
	var received WebhookPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wc, err := NewWebhookClient(5*time.Second, nil)
	require.NoError(t, err)

	svc := newTestService(t)
	svc.webhookClient = wc

	svc.sendSync(&Channel{Webhook: []string{srv.URL}}, "hello webhook", 0, "")
	assert.Equal(t, "hello webhook", received.Text)
}

func TestSendSync_WebhookFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	wc, err := NewWebhookClient(5*time.Second, nil)
	require.NoError(t, err)

	svc := newTestService(t)
	svc.webhookClient = wc

	// Should not panic; failure is logged
	svc.sendSync(&Channel{Webhook: []string{srv.URL}}, "msg", 0, "")
}

func TestSendSync_AllChannelTypes(t *testing.T) {
	// Test delivering to all three channel types simultaneously
	var slackCalled, pushoverCalled atomic.Int32

	slackRT := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		slackCalled.Add(1)
		return newJSONResponse(200, map[string]interface{}{"ok": true}), nil
	})
	pushoverRT := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		pushoverCalled.Add(1)
		return newJSONResponse(200, PushoverResponse{Status: 1, Request: "ok"}), nil
	})

	var webhookCalled atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookCalled.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wc, err := NewWebhookClient(5*time.Second, nil)
	require.NoError(t, err)

	svc := newTestService(t)
	svc.slackClient = slackClientWithRT(slackRT)
	svc.pushoverClient = newPushoverClientWithRT(pushoverRT)
	svc.webhookClient = wc

	ch := &Channel{
		Slack:    []string{"C1"},
		Pushover: []string{"user1"},
		Webhook:  []string{srv.URL},
	}
	svc.sendSync(ch, "multi-channel", 1, "pushover")

	assert.Equal(t, int32(1), slackCalled.Load())
	assert.Equal(t, int32(1), pushoverCalled.Load())
	assert.Equal(t, int32(1), webhookCalled.Load())
}

// ============================================================
// Full lifecycle integration test: NewNotifyService -> Start -> Send -> Stop
// ============================================================

func TestLifecycle_SendAndConsume(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc, err := NewNotifyService(&Config{
		Webhook: &WebhookConfig{Enabled: true, Timeout: 5 * time.Second},
	})
	require.NoError(t, err)

	svc.Start(context.Background())

	ch := &Channel{Webhook: []string{srv.URL}}

	for i := 0; i < 3; i++ {
		err := svc.Send(ch, "lifecycle-test")
		require.NoError(t, err)
	}

	assert.Eventually(t, func() bool {
		return callCount.Load() >= 3
	}, 3*time.Second, 10*time.Millisecond)

	svc.Stop()
	assert.Equal(t, int32(3), callCount.Load())
}

func TestLifecycle_SendWithPriorityAndConsume(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc, err := NewNotifyService(&Config{
		Webhook: &WebhookConfig{Enabled: true, Timeout: 5 * time.Second},
	})
	require.NoError(t, err)

	svc.Start(context.Background())

	ch := &Channel{Webhook: []string{srv.URL}}
	err = svc.SendWithPriority(ch, "priority-test", 2, "siren")
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		return callCount.Load() >= 1
	}, 2*time.Second, 10*time.Millisecond)

	svc.Stop()
}

func TestLifecycle_ContextCancelStopsConsumer(t *testing.T) {
	svc, err := NewNotifyService(&Config{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	svc.Start(ctx)

	// Cancel the parent context
	cancel()

	// Stop should complete quickly since context is already cancelled
	done := make(chan struct{})
	go func() {
		svc.Stop()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() should have returned promptly after context cancellation")
	}
}

// ============================================================
// sendSync — empty channel lists (no-op branches)
// ============================================================

func TestSendSync_EmptySlackChannels(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatal("should not be called for empty slack channels list")
		return nil, nil
	})

	svc := newTestService(t)
	svc.slackClient = slackClientWithRT(rt)
	// Slack list is empty, so it should skip
	svc.sendSync(&Channel{Slack: []string{}}, "msg", 0, "")
}

func TestSendSync_EmptyPushoverUsers(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatal("should not be called for empty pushover users list")
		return nil, nil
	})

	svc := newTestService(t)
	svc.pushoverClient = newPushoverClientWithRT(rt)
	// Pushover list is empty, so it should skip
	svc.sendSync(&Channel{Pushover: []string{}}, "msg", 0, "")
}

func TestSendSync_EmptyWebhookURLs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called for empty webhook URLs list")
	}))
	defer srv.Close()

	wc, err := NewWebhookClient(5*time.Second, nil)
	require.NoError(t, err)

	svc := newTestService(t)
	svc.webhookClient = wc
	// Webhook list is empty, so it should skip
	svc.sendSync(&Channel{Webhook: []string{}}, "msg", 0, "")
}

// ============================================================
// helpers
// ============================================================

// newTestService creates a NotifyService with no clients but a buffered
// message channel, suitable for unit testing Send/SendWithPriority/sendSync.
func newTestService(t *testing.T) *NotifyService {
	t.Helper()
	svc, err := NewNotifyService(&Config{})
	require.NoError(t, err)
	return svc
}

// newTestServiceWithWebhook creates a NotifyService with only a webhook
// client pointed at the given URL, for integration-style lifecycle tests.
func newTestServiceWithWebhook(t *testing.T, webhookURL string) *NotifyService {
	t.Helper()
	svc, err := NewNotifyService(&Config{
		Webhook: &WebhookConfig{Enabled: true, Timeout: 5 * time.Second},
	})
	require.NoError(t, err)
	// The webhookClient already exists; no need to override unless we
	// want to point to a custom URL, which we do via the Channel arg.
	return svc
}
