package storage

import (
	"strings"
	"time"
)

// formatDBTime stores timestamps in a stable UTC RFC3339 form that GORM/SQLite
// can round-trip. Raw driver time.Time binding uses String() and embeds a
// monotonic clock suffix that breaks reads and SQL comparisons.
func formatDBTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// stripMonotonic removes Go's monotonic-clock suffix from legacy DB values.
func stripMonotonic(s string) string {
	if i := strings.Index(s, " m="); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// parseDBTime parses timestamps written by older builds or raw SQL bindings.
func parseDBTime(s string) (time.Time, error) {
	s = stripMonotonic(s)
	if s == "" {
		return time.Time{}, nil
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05.999999999 -0700 CST",
		"2006-01-02 15:04:05.999999999 +0800 CST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05",
	}
	var lastErr error
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		} else {
			lastErr = err
		}
	}
	return time.Time{}, lastErr
}

// effectiveBudgetUpdatedAt returns the best available last-update time for a
// budget row. Legacy rows may have unparsable updated_at in GORM but valid raw strings.
func effectiveBudgetUpdatedAt(updatedAt, createdAt time.Time, updatedAtRaw string) time.Time {
	if !updatedAt.IsZero() {
		return updatedAt
	}
	if t, err := parseDBTime(updatedAtRaw); err == nil && !t.IsZero() {
		return t
	}
	return createdAt
}

// effectivePeriodStart returns when the current budget period anchor began.
func effectivePeriodStart(periodStart, ruleCreatedAt time.Time, periodStartRaw string) time.Time {
	if !periodStart.IsZero() {
		return periodStart
	}
	if t, err := parseDBTime(periodStartRaw); err == nil && !t.IsZero() {
		return t
	}
	return ruleCreatedAt
}
