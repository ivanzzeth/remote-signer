package evm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// token_metadata.go: decodeUint8FromHex
// =============================================================================

func TestDecodeUint8FromHex_EmptyString_CB7(t *testing.T) {
	_, err := decodeUint8FromHex("")
	assert.Error(t, err)
}

func TestDecodeUint8FromHex_InvalidHex_CB7(t *testing.T) {
	_, err := decodeUint8FromHex("0xZZZZ")
	assert.Error(t, err)
}

func TestDecodeUint8FromHex_OutOfRange_CB7(t *testing.T) {
	_, err := decodeUint8FromHex("0xFF") // 255 > 77
	assert.Error(t, err)
}

func TestDecodeUint8FromHex_Valid_CB7(t *testing.T) {
	v, err := decodeUint8FromHex("0x12")
	assert.NoError(t, err)
	assert.Equal(t, 18, v)
}

// =============================================================================
// token_metadata.go: decodeStringFromHex
// =============================================================================

func TestDecodeStringFromHex_EmptyString_CB7(t *testing.T) {
	_, err := decodeStringFromHex("")
	assert.Error(t, err)
}

func TestDecodeStringFromHex_TooShort_CB7(t *testing.T) {
	_, err := decodeStringFromHex("0x1234")
	assert.Error(t, err)
}

// =============================================================================
// token_metadata.go: decodeBoolFromHex
// =============================================================================

func TestDecodeBoolFromHex_EmptyString_CB7(t *testing.T) {
	result := decodeBoolFromHex("")
	assert.False(t, result)
}

func TestDecodeBoolFromHex_InvalidHex_CB7(t *testing.T) {
	result := decodeBoolFromHex("0xZZZZ")
	assert.False(t, result)
}

func TestDecodeBoolFromHex_True_CB7(t *testing.T) {
	result := decodeBoolFromHex("0x0000000000000000000000000000000000000000000000000000000000000001")
	assert.True(t, result)
}

func TestDecodeBoolFromHex_False_CB7(t *testing.T) {
	result := decodeBoolFromHex("0x0000000000000000000000000000000000000000000000000000000000000000")
	assert.False(t, result)
}
