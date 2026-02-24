package views

import (
	"encoding/json"
	"fmt"
)

// MaxPayloadDisplayRunes limits how much of a payload we show in the TUI to keep rendering fast.
const MaxPayloadDisplayRunes = 4096

// FormatPayloadForDisplay pretty-prints JSON payload and truncates if too long.
func FormatPayloadForDisplay(raw []byte) string {
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Sprintf("(invalid JSON: %v)", err)
	}
	indented, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(raw)
	}
	s := string(indented)
	if len([]rune(s)) > MaxPayloadDisplayRunes {
		runes := []rune(s)
		s = string(runes[:MaxPayloadDisplayRunes]) + "\n\n... (truncated, " + fmt.Sprintf("%d", len(raw)) + " bytes total)"
	}
	return s
}
