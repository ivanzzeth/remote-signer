package server

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/homepath"
)

// daemonizedEnv marks a process that has already been backgrounded, so the
// re-executed child does not daemonize again (which would fork forever).
const daemonizedEnv = "REMOTE_SIGNER_DAEMONIZED"

// daemonize re-executes the current binary in the background, detached from the
// controlling terminal, with stdout/stderr redirected to the daemon log file
// (~/.remote-signer/remote-signer.log). The parent prints the child PID and the
// log path, then returns nil so the foreground process exits. The child runs
// `server start` normally (with daemonizedEnv set) and writes the PID file.
//
// args are the original `server start` args; the --daemon/-daemon flag is
// stripped before re-exec.
func daemonize(args []string) error {
	if _, err := homepath.EnsureHome(); err != nil {
		return fmt.Errorf("ensure remote-signer home: %w", err)
	}
	logPath, err := homepath.LogPath()
	if err != nil {
		return fmt.Errorf("resolve log path: %w", err)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", logPath, err)
	}
	defer logFile.Close()

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	// Reconstruct the child argv: `server start <args-without-daemon-flag>`.
	childArgs := append([]string{"server", "start"}, stripDaemonFlag(args)...)

	cmd := exec.Command(self, childArgs...)
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = append(os.Environ(), daemonizedEnv+"=1")
	cmd.SysProcAttr = detachSysProcAttr() // OS-specific: new session / detached process

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start background process: %w", err)
	}
	pid := cmd.Process.Pid // capture before Release (which invalidates Pid)
	// Release so the child is not reaped/tied to this exiting parent.
	_ = cmd.Process.Release()

	fmt.Fprintf(os.Stderr, "remote-signer started in background (pid %d)\n", pid)
	fmt.Fprintf(os.Stderr, "logs: %s\n", logPath)
	return nil
}

// stripDaemonFlag removes the --daemon / -daemon boolean flag (in any of its
// forms) from the forwarded args so the re-executed child runs in the foreground.
func stripDaemonFlag(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--daemon" || a == "-daemon" ||
			strings.HasPrefix(a, "--daemon=") || strings.HasPrefix(a, "-daemon=") {
			continue
		}
		out = append(out, a)
	}
	return out
}

// writePIDFile records the current process PID so `server stop` can find it.
func writePIDFile() {
	path, err := homepath.PIDPath()
	if err != nil {
		return
	}
	_ = os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0600)
}

// removePIDFile deletes the PID file on clean shutdown. Best-effort.
func removePIDFile() {
	if path, err := homepath.PIDPath(); err == nil {
		_ = os.Remove(path)
	}
}
