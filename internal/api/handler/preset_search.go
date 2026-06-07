package handler

import "strings"

// presetMatchesQuery returns true when q is empty or matches any searchable
// field on the preset list item (case-insensitive substring).
func presetMatchesQuery(item PresetListItem, q string) bool {
	q = strings.TrimSpace(strings.ToLower(q))
	if q == "" {
		return true
	}
	if strings.Contains(strings.ToLower(item.ID), q) {
		return true
	}
	if strings.Contains(strings.ToLower(item.Name), q) {
		return true
	}
	if strings.Contains(strings.ToLower(item.Description), q) {
		return true
	}
	for _, tid := range item.TemplateIDs {
		if strings.Contains(strings.ToLower(tid), q) {
			return true
		}
	}
	return false
}
