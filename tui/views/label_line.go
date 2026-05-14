package views

import (
	"strings"
)

// HumanLabelLine formats display name and tags for TUI list rows (or empty if neither).
func HumanLabelLine(displayName string, tags []string) string {
	var parts []string
	if dn := strings.TrimSpace(displayName); dn != "" {
		parts = append(parts, dn)
	}
	if len(tags) > 0 {
		parts = append(parts, "tags: "+strings.Join(tags, ", "))
	}
	if len(parts) == 0 {
		return ""
	}
	line := strings.Join(parts, " · ")
	const maxLen = 96
	if len(line) <= maxLen {
		return line
	}
	return line[:maxLen-1] + "…"
}

// ParseTagsCSV splits comma-separated tags (trimmed, empty parts dropped).
func ParseTagsCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
