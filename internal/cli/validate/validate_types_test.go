package validate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolvePath_Absolute(t *testing.T) {
	result := resolvePath("/base", "/absolute/path")
	assert.Equal(t, "/absolute/path", result)
}

func TestResolvePath_Relative(t *testing.T) {
	result := resolvePath("/base", "relative/path")
	assert.Equal(t, "/base/relative/path", result)
}

func TestResolvePath_Empty(t *testing.T) {
	result := resolvePath("/base", "")
	assert.Equal(t, "", result)
}
