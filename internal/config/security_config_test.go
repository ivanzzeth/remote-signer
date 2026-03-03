package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func boolPtr(b bool) *bool { return &b }

func TestIsRulesAPIReadonly(t *testing.T) {
	t.Run("defaults to true when nil", func(t *testing.T) {
		sc := SecurityConfig{RulesAPIReadonly: nil}
		assert.True(t, sc.IsRulesAPIReadonly())
	})

	t.Run("returns true when set to true", func(t *testing.T) {
		sc := SecurityConfig{RulesAPIReadonly: boolPtr(true)}
		assert.True(t, sc.IsRulesAPIReadonly())
	})

	t.Run("returns false when set to false", func(t *testing.T) {
		sc := SecurityConfig{RulesAPIReadonly: boolPtr(false)}
		assert.False(t, sc.IsRulesAPIReadonly())
	})
}

func TestIsSignersAPIReadonly(t *testing.T) {
	t.Run("defaults to false when nil", func(t *testing.T) {
		sc := SecurityConfig{SignersAPIReadonly: nil}
		assert.False(t, sc.IsSignersAPIReadonly())
	})

	t.Run("returns true when set to true", func(t *testing.T) {
		sc := SecurityConfig{SignersAPIReadonly: boolPtr(true)}
		assert.True(t, sc.IsSignersAPIReadonly())
	})

	t.Run("returns false when set to false", func(t *testing.T) {
		sc := SecurityConfig{SignersAPIReadonly: boolPtr(false)}
		assert.False(t, sc.IsSignersAPIReadonly())
	})
}
