package evm

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestCategorizeSignError(t *testing.T) {
	const addr = "0xABCD"

	tests := []struct {
		name           string
		err            error
		wantStatus     int
		wantMessage    string
		wantNotContain string // if set, message must NOT contain this substring
	}{
		{
			name:       "signer locked",
			err:        types.ErrSignerLocked,
			wantStatus: http.StatusForbidden,
			wantMessage: fmt.Sprintf(
				"signer is locked: %s — unlock via POST /api/v1/evm/signers/%s/unlock", addr, addr,
			),
		},
		{
			name:        "wrapped signer locked",
			err:         fmt.Errorf("keystore error: %w", types.ErrSignerLocked),
			wantStatus:  http.StatusForbidden,
			wantMessage: fmt.Sprintf("signer is locked: %s — unlock via POST /api/v1/evm/signers/%s/unlock", addr, addr),
		},
		{
			name:        "not found",
			err:         types.ErrNotFound,
			wantStatus:  http.StatusNotFound,
			wantMessage: fmt.Sprintf("signer not found: %s", addr),
		},
		{
			name:        "signer not found",
			err:         types.ErrSignerNotFound,
			wantStatus:  http.StatusNotFound,
			wantMessage: fmt.Sprintf("signer not found: %s", addr),
		},
		{
			name:        "invalid payload",
			err:         types.ErrInvalidPayload,
			wantStatus:  http.StatusBadRequest,
			wantMessage: types.ErrInvalidPayload.Error(),
		},
		{
			name:        "wrapped invalid payload",
			err:         fmt.Errorf("field X: %w", types.ErrInvalidPayload),
			wantStatus:  http.StatusBadRequest,
			wantMessage: fmt.Sprintf("field X: %s", types.ErrInvalidPayload.Error()),
		},
		{
			name:        "manual approval disabled",
			err:         service.ErrManualApprovalDisabled,
			wantStatus:  http.StatusForbidden,
			wantMessage: "no matching rule and manual approval is disabled",
		},
		{
			name:           "unknown internal error is sanitized",
			err:            fmt.Errorf("bolt DB open /var/data/signer.db: permission denied"),
			wantStatus:     http.StatusInternalServerError,
			wantMessage:    "sign request failed",
			wantNotContain: "bolt DB",
		},
		{
			name:           "wrapped internal error is sanitized",
			err:            fmt.Errorf("keystore at /home/user/.keys: %w", fmt.Errorf("decryption failed")),
			wantStatus:     http.StatusInternalServerError,
			wantMessage:    "sign request failed",
			wantNotContain: "/home/user",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := categorizeSignError(tc.err, addr)
			if result.StatusCode != tc.wantStatus {
				t.Errorf("status: got %d, want %d", result.StatusCode, tc.wantStatus)
			}
			if result.Message != tc.wantMessage {
				t.Errorf("message: got %q, want %q", result.Message, tc.wantMessage)
			}
			if tc.wantNotContain != "" {
				if contains(result.Message, tc.wantNotContain) {
					t.Errorf("message %q must not contain %q", result.Message, tc.wantNotContain)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && searchSubstring(s, substr)))
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
