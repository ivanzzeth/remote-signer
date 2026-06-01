package server

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/homepath"
)

// Stop terminates a running `server start` daemon. It reads the PID file written
// at startup (~/.remote-signer/remote-signer.pid), sends a graceful stop signal,
// and waits for the process to exit. Returns nil if no daemon is running.
func Stop(args []string) error {
	fs := flag.NewFlagSet("remote-signer server stop", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 30*time.Second, "max time to wait for the daemon to exit")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	pidPath, err := homepath.PIDPath()
	if err != nil {
		return fmt.Errorf("resolve pid path: %w", err)
	}
	raw, err := os.ReadFile(pidPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "remote-signer is not running (no pid file)")
			return nil
		}
		return fmt.Errorf("read pid file %s: %w", pidPath, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("invalid pid file %s: %w", pidPath, err)
	}

	if !processAlive(pid) {
		fmt.Fprintf(os.Stderr, "remote-signer (pid %d) is not running; removing stale pid file\n", pid)
		_ = os.Remove(pidPath)
		return nil
	}

	if err := signalStop(pid); err != nil {
		return fmt.Errorf("signal pid %d: %w", pid, err)
	}
	fmt.Fprintf(os.Stderr, "stopping remote-signer (pid %d)...\n", pid)

	deadline := time.Now().Add(*timeout)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			_ = os.Remove(pidPath)
			fmt.Fprintln(os.Stderr, "remote-signer stopped")
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("remote-signer (pid %d) did not exit within %s", pid, *timeout)
}
