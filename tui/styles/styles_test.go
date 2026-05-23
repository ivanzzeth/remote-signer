package styles

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetStatusStyle(t *testing.T) {
	tests := []string{"pending", "authorizing", "signing", "completed", "rejected", "failed", "unknown", ""}
	for _, status := range tests {
		t.Run(status, func(t *testing.T) {
			s := GetStatusStyle(status)
			assert.NotNil(t, s)
		})
	}
}

func TestGetSeverityStyle(t *testing.T) {
	tests := []struct {
		severity string
	}{
		{"info"},
		{"warning"},
		{"critical"},
		{"unknown"},
		{""},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			s := GetSeverityStyle(tt.severity)
			assert.NotNil(t, s)
		})
	}
}

func TestStylesAreInitialized(t *testing.T) {
	assert.NotNil(t, BaseStyle)
	assert.NotNil(t, TitleStyle)
	assert.NotNil(t, SubtitleStyle)
	assert.NotNil(t, BoxStyle)
	assert.NotNil(t, ButtonStyle)
	assert.NotNil(t, ErrorStyle)
	assert.NotNil(t, SuccessStyle)
	assert.NotNil(t, WarningStyle)
	assert.NotNil(t, HelpStyle)
	assert.NotNil(t, SpinnerStyle)
	assert.NotNil(t, BadgeStyle)
}
