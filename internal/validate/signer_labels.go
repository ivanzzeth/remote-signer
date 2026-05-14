package validate

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	maxSignerDisplayNameRunes = 256
	maxSignerTagCount         = 32
	maxSignerTagRunes         = 64
)

// NormalizeSignerDisplayName trims whitespace and truncates to a safe maximum length.
func NormalizeSignerDisplayName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if utf8.RuneCountInString(s) <= maxSignerDisplayNameRunes {
		return s
	}
	runes := []rune(s)
	if len(runes) > maxSignerDisplayNameRunes {
		return string(runes[:maxSignerDisplayNameRunes])
	}
	return s
}

// NormalizeSignerTags trims, deduplicates case-insensitively, enforces count/length limits.
func NormalizeSignerTags(tags []string) ([]string, error) {
	if len(tags) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if utf8.RuneCountInString(t) > maxSignerTagRunes {
			return nil, fmt.Errorf("tag longer than %d characters", maxSignerTagRunes)
		}
		key := strings.ToLower(t)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, t)
		if len(out) > maxSignerTagCount {
			return nil, fmt.Errorf("at most %d tags allowed", maxSignerTagCount)
		}
	}
	return out, nil
}

// SignerHasTag returns true if tags contain q (case-insensitive).
func SignerHasTag(tags []string, q string) bool {
	q = strings.TrimSpace(strings.ToLower(q))
	if q == "" {
		return true
	}
	for _, t := range tags {
		if strings.EqualFold(strings.TrimSpace(t), q) {
			return true
		}
	}
	return false
}
