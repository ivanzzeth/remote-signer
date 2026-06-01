//go:build windows

package server

import (
	"os"
	"syscall"
)

const (
	createNewProcessGroup = 0x00000200 // CREATE_NEW_PROCESS_GROUP
	detachedProcess       = 0x00000008 // DETACHED_PROCESS
)

// detachSysProcAttr starts the child detached from the parent console so it
// keeps running in the background after the foreground process exits.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: createNewProcessGroup | detachedProcess}
}

// signalStop terminates the process. Windows has no SIGTERM equivalent for an
// unrelated process, so use the OS Kill.
func signalStop(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

// processAlive reports whether a process with the given PID exists.
func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Windows FindProcess succeeds even for dead PIDs; Signal(0) probes it.
	return p.Signal(syscall.Signal(0)) == nil
}
