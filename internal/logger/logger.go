package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Module represents different modules in the system
type Module string

const (
	ModuleAPI         Module = "api"
	ModuleAuth        Module = "auth"
	ModuleChain       Module = "chain"
	ModuleEVM         Module = "evm"
	ModuleNotify      Module = "notify"
	ModuleRule        Module = "rule"
	ModuleService     Module = "service"
	ModuleStateMachine Module = "statemachine"
	ModuleStorage     Module = "storage"
	ModuleSystem      Module = "system"
)

var (
	// Global logger instance
	globalLogger zerolog.Logger

	// Module loggers with context (pointers for zerolog chain API)
	moduleLoggers = make(map[Module]*zerolog.Logger)
)

// Init initializes the global logger and module loggers
func Init(level zerolog.Level, pretty bool) {
	// Configure global logger
	output := os.Stdout
	if pretty {
		// Use console writer for pretty output in development
		globalLogger = zerolog.New(zerolog.ConsoleWriter{
			Out:        output,
			TimeFormat: time.RFC3339,
		}).With().Timestamp().Logger()
	} else {
		// Use JSON format for production
		globalLogger = zerolog.New(output).With().Timestamp().Logger()
	}

	// Set global log level
	zerolog.SetGlobalLevel(level)

	// Initialize module loggers with context (each needs its own variable so pointer is stable)
	lAPI := globalLogger.With().Str("module", string(ModuleAPI)).Logger()
	moduleLoggers[ModuleAPI] = &lAPI
	lAuth := globalLogger.With().Str("module", string(ModuleAuth)).Logger()
	moduleLoggers[ModuleAuth] = &lAuth
	lChain := globalLogger.With().Str("module", string(ModuleChain)).Logger()
	moduleLoggers[ModuleChain] = &lChain
	lEVM := globalLogger.With().Str("module", string(ModuleEVM)).Logger()
	moduleLoggers[ModuleEVM] = &lEVM
	lNotify := globalLogger.With().Str("module", string(ModuleNotify)).Logger()
	moduleLoggers[ModuleNotify] = &lNotify
	lRule := globalLogger.With().Str("module", string(ModuleRule)).Logger()
	moduleLoggers[ModuleRule] = &lRule
	lService := globalLogger.With().Str("module", string(ModuleService)).Logger()
	moduleLoggers[ModuleService] = &lService
	lSM := globalLogger.With().Str("module", string(ModuleStateMachine)).Logger()
	moduleLoggers[ModuleStateMachine] = &lSM
	lStorage := globalLogger.With().Str("module", string(ModuleStorage)).Logger()
	moduleLoggers[ModuleStorage] = &lStorage
	lSystem := globalLogger.With().Str("module", string(ModuleSystem)).Logger()
	moduleLoggers[ModuleSystem] = &lSystem
}

// Get returns the logger for a specific module (pointer for zerolog chain API)
func Get(module Module) *zerolog.Logger {
	if l, ok := moduleLoggers[module]; ok {
		return l
	}
	return &globalLogger
}

// GetGlobal returns the global logger
func GetGlobal() *zerolog.Logger {
	return &globalLogger
}

// WithContext adds additional context fields to a module logger
func WithContext(module Module, fields map[string]interface{}) zerolog.Logger {
	log := Get(module)
	ctx := log.With()
	for k, v := range fields {
		ctx = ctx.Interface(k, v)
	}
	return ctx.Logger()
}

// API returns the API module logger
func API() *zerolog.Logger {
	return Get(ModuleAPI)
}

// Auth returns the auth module logger
func Auth() *zerolog.Logger {
	return Get(ModuleAuth)
}

// Chain returns the chain module logger
func Chain() *zerolog.Logger {
	return Get(ModuleChain)
}

// EVM returns the EVM module logger
func EVM() *zerolog.Logger {
	return Get(ModuleEVM)
}

// Notify returns the notify module logger
func Notify() *zerolog.Logger {
	return Get(ModuleNotify)
}

// Rule returns the rule module logger
func Rule() *zerolog.Logger {
	return Get(ModuleRule)
}

// Service returns the service module logger
func Service() *zerolog.Logger {
	return Get(ModuleService)
}

// StateMachine returns the state machine module logger
func StateMachine() *zerolog.Logger {
	return Get(ModuleStateMachine)
}

// Storage returns the storage module logger
func Storage() *zerolog.Logger {
	return Get(ModuleStorage)
}

// System returns the system module logger
func System() *zerolog.Logger {
	return Get(ModuleSystem)
}
