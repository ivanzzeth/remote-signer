package views

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatPayloadForDisplay_ValidJSON(t *testing.T) {
	result := FormatPayloadForDisplay([]byte(`{"key":"value","num":42}`))
	assert.Contains(t, result, `"key"`)
	assert.Contains(t, result, `"value"`)
	assert.Contains(t, result, `"num"`)
	assert.Contains(t, result, `42`)
}

func TestFormatPayloadForDisplay_Array(t *testing.T) {
	result := FormatPayloadForDisplay([]byte(`[1,2,3]`))
	assert.Contains(t, result, "1")
	assert.Contains(t, result, "2")
	assert.Contains(t, result, "3")
}

func TestFormatPayloadForDisplay_InvalidJSON(t *testing.T) {
	result := FormatPayloadForDisplay([]byte(`not json`))
	assert.Contains(t, result, "invalid JSON")
}

func TestFormatPayloadForDisplay_Empty(t *testing.T) {
	result := FormatPayloadForDisplay([]byte{})
	assert.Contains(t, result, "invalid JSON")
}

func TestFormatPayloadForDisplay_Truncation(t *testing.T) {
	// Generate a large JSON payload that exceeds MaxPayloadDisplayRunes
	large := make([]byte, 0, MaxPayloadDisplayRunes+1000)
	large = append(large, []byte(`{"data":"`)...)
	for i := 0; i < MaxPayloadDisplayRunes; i++ {
		large = append(large, 'x')
	}
	large = append(large, []byte(`"}`)...)

	result := FormatPayloadForDisplay(large)
	assert.Contains(t, result, "... (truncated")
}

func TestFormatPayloadForDisplay_NestedJSON(t *testing.T) {
	result := FormatPayloadForDisplay([]byte(`{"level1":{"level2":[1,2,3],"name":"test"}}`))
	assert.Contains(t, result, "level1")
	assert.Contains(t, result, "level2")
	assert.Contains(t, result, "test")
}
