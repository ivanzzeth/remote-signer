//go:build !linux

package server

import "log/slog"

// checkSwapEnabled is a no-op on non-Linux platforms.
func checkSwapEnabled(_ *slog.Logger) {}

// hardenProcessMemory is a no-op on non-Linux platforms.
func hardenProcessMemory(_ *slog.Logger) {}
