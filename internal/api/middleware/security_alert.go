package middleware

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/notify"
)

// SecurityAlertType categorizes security events for rate limiting.
type SecurityAlertType string

const (
	AlertIPBlocked     SecurityAlertType = "ip_blocked"
	AlertAuthFailure   SecurityAlertType = "auth_failure"
	AlertNonceReplay   SecurityAlertType = "nonce_replay"
	AlertDisabledKey   SecurityAlertType = "disabled_key"
	AlertExpiredKey     SecurityAlertType = "expired_key"
	AlertAdminDenied   SecurityAlertType = "admin_denied"
	AlertRateLimitIP   SecurityAlertType = "rate_limit_ip"
	AlertRateLimitKey  SecurityAlertType = "rate_limit_key"
	AlertChainDenied   SecurityAlertType = "chain_denied"
	AlertSignerDenied  SecurityAlertType = "signer_denied"
)

// SecurityAlertService sends real-time security alerts with per-source
// rate limiting to prevent notification flooding.
type SecurityAlertService struct {
	notifyService *notify.NotifyService
	channel       *notify.Channel
	logger        *slog.Logger

	// Rate limiting: at most one alert per (type, source) per cooldown window.
	mu       sync.Mutex
	cooldown time.Duration
	lastSent map[string]time.Time // key: "type:source"
}

// NewSecurityAlertService creates a new security alert service.
// cooldown controls the minimum interval between alerts for the same (type, source).
func NewSecurityAlertService(
	notifyService *notify.NotifyService,
	channel *notify.Channel,
	logger *slog.Logger,
	cooldown time.Duration,
) (*SecurityAlertService, error) {
	if notifyService == nil {
		return nil, fmt.Errorf("notify service is required")
	}
	if channel == nil {
		return nil, fmt.Errorf("notify channel is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if cooldown <= 0 {
		cooldown = 5 * time.Minute
	}

	return &SecurityAlertService{
		notifyService: notifyService,
		channel:       channel,
		logger:        logger,
		cooldown:      cooldown,
		lastSent:      make(map[string]time.Time),
	}, nil
}

// Alert sends a security alert if not rate-limited.
// source identifies the origin (IP, API key ID, etc.) for rate limiting.
func (s *SecurityAlertService) Alert(alertType SecurityAlertType, source, message string) {
	key := string(alertType) + ":" + source

	s.mu.Lock()
	last, exists := s.lastSent[key]
	now := time.Now()
	if exists && now.Sub(last) < s.cooldown {
		s.mu.Unlock()
		s.logger.Debug("security alert rate-limited",
			"type", string(alertType),
			"source", source,
			"cooldown_remaining", s.cooldown-now.Sub(last),
		)
		return
	}
	s.lastSent[key] = now
	s.mu.Unlock()

	if err := s.notifyService.SendWithPriority(s.channel, message, 1, "siren"); err != nil {
		s.logger.Error("failed to send security alert",
			"type", string(alertType),
			"source", source,
			"error", err,
		)
	}
}

// Cleanup removes expired rate limit entries. Call periodically.
func (s *SecurityAlertService) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, last := range s.lastSent {
		if now.Sub(last) >= s.cooldown*2 {
			delete(s.lastSent, key)
		}
	}
}

// StartCleanupRoutine starts a goroutine to periodically clean up expired entries.
func (s *SecurityAlertService) StartCleanupRoutine(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				s.Cleanup()
			case <-stop:
				ticker.Stop()
				return
			}
		}
	}()
}
