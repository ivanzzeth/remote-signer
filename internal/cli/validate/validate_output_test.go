package validate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInterfaceMapToStringMap_Nil(t *testing.T) {
	result := interfaceMapToStringMap(nil)
	assert.Nil(t, result)
}

func TestInterfaceMapToStringMap_Empty(t *testing.T) {
	result := interfaceMapToStringMap(map[string]interface{}{})
	assert.Nil(t, result)
}

func TestInterfaceMapToStringMap_StringValues(t *testing.T) {
	result := interfaceMapToStringMap(map[string]interface{}{
		"key1": "val1",
		"key2": "val2",
	})
	assert.Equal(t, "val1", result["key1"])
	assert.Equal(t, "val2", result["key2"])
}

func TestInterfaceMapToStringMap_MixedValues(t *testing.T) {
	result := interfaceMapToStringMap(map[string]interface{}{
		"str":   "hello",
		"num":   42,
		"nil":   nil,
		"bool":  true,
		"float": 3.14,
	})
	assert.Equal(t, "hello", result["str"])
	assert.Equal(t, "42", result["num"])
	assert.Equal(t, "", result["nil"])
	assert.Equal(t, "true", result["bool"])
	assert.Equal(t, "3.14", result["float"])
}
