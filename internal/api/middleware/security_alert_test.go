package middleware

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/notify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecurityAlertService_Valid(t *testing.T) {
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ch := &notify.Channel{}
	sas, err := NewSecurityAlertService(svc, ch, logger, 1*time.Minute)
	require.NoError(t, err)
	require.NotNil(t, sas)
	assert.Equal(t, 1*time.Minute, sas.cooldown)
}

func TestNewSecurityAlertService_NilNotifyService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	_, err := NewSecurityAlertService(nil, &notify.Channel{}, logger, 1*time.Minute)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "notify service is required")
}

func TestNewSecurityAlertService_NilChannel(t *testing.T) {
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	_, err = NewSecurityAlertService(svc, nil, logger, 1*time.Minute)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "notify channel is required")
}

func TestNewSecurityAlertService_DefaultCooldown(t *testing.T) {
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	sas, err := NewSecurityAlertService(svc, &notify.Channel{}, logger, 0)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, sas.cooldown)
}

func TestNewSecurityAlertService_NilLogger(t *testing.T) {
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)

	_, err = NewSecurityAlertService(svc, &notify.Channel{}, nil, 1*time.Minute)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

func TestSecurityAlertService_Alert(t *testing.T) {
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)
	svc.Start(context.Background())
	defer svc.Stop()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ch := &notify.Channel{}
	sas, err := NewSecurityAlertService(svc, ch, logger, 1*time.Minute)
	require.NoError(t, err)

	// Alert should not panic and should process the message.
	sas.Alert(AlertIPBlocked, "192.168.1.1", "test message")
	time.Sleep(100 * time.Millisecond)
}

func TestSecurityAlertService_AlertRespectsCooldown(t *testing.T) {
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)
	svc.Start(context.Background())
	defer svc.Stop()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ch := &notify.Channel{}
	sas, err := NewSecurityAlertService(svc, ch, logger, 10*time.Second)
	require.NoError(t, err)

	// Send the first alert.
	sas.Alert(AlertIPBlocked, "192.168.1.1", "first alert")
	time.Sleep(50 * time.Millisecond)

	// The cooldown map should have an entry; second alert for same type+source
	// should be rate-limited (no panic).
	sas.Alert(AlertIPBlocked, "192.168.1.1", "second alert (should be rate-limited)")
	time.Sleep(50 * time.Millisecond)

	// A different source should NOT be rate-limited.
	sas.Alert(AlertIPBlocked, "10.0.0.1", "third alert (different source)")
	time.Sleep(50 * time.Millisecond)

	// A different alert type should NOT be rate-limited.
	sas.Alert(AlertAuthFailure, "192.168.1.1", "fourth alert (different type)")
	time.Sleep(50 * time.Millisecond)
}

func TestSecurityAlertService_Cleanup(t *testing.T) {
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ch := &notify.Channel{}
	sas, err := NewSecurityAlertService(svc, ch, logger, 1*time.Millisecond)
	require.NoError(t, err)

	// Add an entry by sending an alert.
	sas.Alert(AlertIPBlocked, "192.168.1.1", "test")
	time.Sleep(10 * time.Millisecond)

	// Wait for cooldown*2 to pass so the entry becomes stale.
	time.Sleep(5 * time.Millisecond)

	sas.Cleanup()

	// After cleanup, the stale entry should be removed.
	sas.mu.Lock()
	require.Empty(t, sas.lastSent, "stale entries should be cleaned up")
	sas.mu.Unlock()
}

func TestSecurityAlertService_StartCleanupRoutine(t *testing.T) {
	svc, err := notify.NewNotifyService(&notify.Config{})
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ch := &notify.Channel{}
	sas, err := NewSecurityAlertService(svc, ch, logger, 1*time.Minute)
	require.NoError(t, err)

	stop := make(chan struct{})
	sas.StartCleanupRoutine(50*time.Millisecond, stop)

	// Let it run briefly.
	time.Sleep(150 * time.Millisecond)

	// Stop the routine.
	close(stop)
	time.Sleep(50 * time.Millisecond)
}
