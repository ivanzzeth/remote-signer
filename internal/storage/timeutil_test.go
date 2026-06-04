package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDBTime_LegacyGoStringWithMonotonic(t *testing.T) {
	raw := "2026-06-02 00:15:42.690163069 +0800 CST m=+1815.275862388"
	tm, err := parseDBTime(raw)
	require.NoError(t, err)
	assert.Equal(t, 2026, tm.Year())
	assert.Equal(t, time.June, tm.Month())
	assert.Equal(t, 1, tm.Day()) // stored as UTC after parse
	assert.Equal(t, time.UTC, tm.Location())
}

func TestParseDBTime_RFC3339Nano(t *testing.T) {
	raw := "2026-06-04T14:26:16.821323089Z"
	tm, err := parseDBTime(raw)
	require.NoError(t, err)
	assert.Equal(t, 2026, tm.Year())
	assert.Equal(t, time.UTC, tm.Location())
}

func TestFormatDBTime_UTC(t *testing.T) {
	tm := time.Date(2026, 6, 4, 22, 0, 0, 123, time.FixedZone("CST", 8*3600))
	assert.Equal(t, "2026-06-04T14:00:00.000000123Z", formatDBTime(tm))
}

func TestEffectiveBudgetUpdatedAt_FallsBackToRaw(t *testing.T) {
	raw := "2026-06-02 00:15:42.690163069 +0800 CST m=+1815.275862388"
	got := effectiveBudgetUpdatedAt(time.Time{}, time.Time{}, raw)
	assert.Equal(t, 2026, got.Year())
}
