package logger

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestInitDefault(t *testing.T) {
	Init(zerolog.InfoLevel, false)
	assert.NotNil(t, GetGlobal())
	assert.NotNil(t, Get(ModuleAPI))
}

func TestGetGlobal(t *testing.T) {
	Init(zerolog.DebugLevel, false)
	l := GetGlobal()
	assert.NotNil(t, l)
}

func TestGet_ExistingModule(t *testing.T) {
	Init(zerolog.InfoLevel, false)
	l := Get(ModuleEVM)
	assert.NotNil(t, l)
}

func TestGet_UnknownModule(t *testing.T) {
	Init(zerolog.InfoLevel, false)
	l := Get(Module("nonexistent"))
	assert.NotNil(t, l)
	assert.Equal(t, GetGlobal(), l)
}

func TestWithContext(t *testing.T) {
	Init(zerolog.InfoLevel, false)
	l := WithContext(ModuleAPI, map[string]interface{}{"key": "val"})
	assert.NotNil(t, l)
}

func TestWithContext_UnknownModule(t *testing.T) {
	Init(zerolog.InfoLevel, false)
	l := WithContext(Module("bogus"), map[string]interface{}{"k": "v"})
	assert.NotNil(t, l)
}

func TestModuleGetters(t *testing.T) {
	Init(zerolog.InfoLevel, false)
	assert.NotNil(t, API())
	assert.NotNil(t, Auth())
	assert.NotNil(t, Chain())
	assert.NotNil(t, EVM())
	assert.NotNil(t, Notify())
	assert.NotNil(t, Rule())
	assert.NotNil(t, Service())
	assert.NotNil(t, StateMachine())
	assert.NotNil(t, Storage())
	assert.NotNil(t, System())
}

func TestInitPretty(t *testing.T) {
	Init(zerolog.WarnLevel, true)
	assert.NotNil(t, GetGlobal())
}
