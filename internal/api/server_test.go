package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultServerConfig(t *testing.T) {
	cfg := DefaultServerConfig()
	assert.Equal(t, "127.0.0.1", cfg.Host)
	assert.Equal(t, 8080, cfg.Port)
	assert.Equal(t, 30*time.Second, cfg.ReadTimeout)
	assert.Equal(t, 30*time.Second, cfg.WriteTimeout)
	assert.False(t, cfg.TLSEnabled)
}
