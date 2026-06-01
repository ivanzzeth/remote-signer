//go:build !windows

package server

import "syscall"

// detachSysProcAttr starts the child in a new session (setsid) so it is fully
// detached from the controlling terminal and survives the parent exiting.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// signalStop asks the process to terminate gracefully (SIGTERM), letting the
// daemon run its shutdown path (HTTP drain, PID file cleanup).
func signalStop(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}

// processAlive reports whether a process with the given PID exists.
func processAlive(pid int) bool {
	// signal 0 performs error checking without delivering a signal.
	return syscall.Kill(pid, 0) == nil
}
