//go:build integration

// Package integration runs black-box tests against the shipped remote-signer
// binary. See README.md in this directory for the running instructions and
// scope.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// binaryPath is the absolute path to the remote-signer binary used by every
// test. Resolved once in TestMain via $REMOTE_SIGNER_BIN or a one-shot build.
var binaryPath string

func TestMain(m *testing.M) {
	if explicit := os.Getenv("REMOTE_SIGNER_BIN"); explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			fmt.Fprintf(os.Stderr, "REMOTE_SIGNER_BIN=%s: %v\n", explicit, err)
			os.Exit(1)
		}
		binaryPath = explicit
		os.Exit(m.Run())
	}
	tmp, err := os.MkdirTemp("", "remote-signer-itest-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create tempdir:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)
	out := filepath.Join(tmp, "remote-signer")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/remote-signer")
	cmd.Dir = repoRoot()
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if buildOut, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "go build remote-signer: %v\n%s\n", err, buildOut)
		os.Exit(1)
	}
	binaryPath = out
	os.Exit(m.Run())
}

// repoRoot walks up from this file's directory until it finds the go.mod.
func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	return "."
}

// freePort asks the kernel for an unused TCP port and returns it. There is a
// tiny race window between Close and the daemon binding, but it has been
// reliable in practice and avoids a fixed port collision between parallel
// tests.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen :0: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return port
}

// daemon wraps a running remote-signer subprocess for a single test.
type daemon struct {
	t          *testing.T
	home       string
	configPath string
	port       int
	cmd        *exec.Cmd
	logFile    *os.File
}

// daemonOption tweaks how a daemon is launched.
type daemonOption func(*daemonConfig)

type daemonConfig struct {
	preWriteConfig bool   // when true, write a custom config.yaml with the allocated port before starting
	rawConfigYAML  string // override the YAML written when preWriteConfig is set
	skipReady      bool   // skip polling /health (useful when expecting startup failure)
}

// withCustomConfig writes the given YAML as the daemon's config.yaml before
// launch. The placeholder __PORT__ is replaced with the assigned port.
func withCustomConfig(yaml string) daemonOption {
	return func(c *daemonConfig) {
		c.preWriteConfig = true
		c.rawConfigYAML = yaml
	}
}

// expectStartupFailure starts the daemon but does not wait for /health. Use
// for negative-path tests that assert the process exits with an error.
func expectStartupFailure() daemonOption {
	return func(c *daemonConfig) { c.skipReady = true }
}

// startDaemon builds a fresh tempdir as $REMOTE_SIGNER_HOME, picks a free
// port, optionally pre-writes config.yaml, launches the binary as a
// subprocess, and (unless skipReady) waits for /health to respond. Cleanup is
// registered with t so SIGTERM goes to the daemon when the test returns.
func startDaemon(t *testing.T, opts ...daemonOption) *daemon {
	t.Helper()
	cfg := daemonConfig{}
	for _, o := range opts {
		o(&cfg)
	}

	// Point REMOTE_SIGNER_HOME at a non-existent subpath so the daemon's
	// EnsureHome() actually creates it (and tests can assert the 0700 mode
	// the daemon applies). t.TempDir() itself is 0755 because the testing
	// package created it; the daemon's home is one level deeper.
	tmpRoot := t.TempDir()
	home := filepath.Join(tmpRoot, "rs-home")
	port := freePort(t)

	// Daemon stdout/stderr capture lives in tmpRoot, not inside home, so the
	// daemon truly owns home-dir creation and the test can observe the 0700
	// mode it applies.
	logPath := filepath.Join(tmpRoot, "daemon.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create daemon log: %v", err)
	}

	// Custom config lives OUTSIDE the home dir so the daemon's home-dir
	// creation path runs without us pre-creating it. The DSN still points
	// inside home; the daemon creates home (and the DB file inside) itself.
	configPath := filepath.Join(tmpRoot, "config.yaml")
	if cfg.preWriteConfig {
		yaml := strings.ReplaceAll(cfg.rawConfigYAML, "__PORT__", strconv.Itoa(port))
		yaml = strings.ReplaceAll(yaml, "__HOME__", home)
		if err := os.WriteFile(configPath, []byte(yaml), 0600); err != nil {
			t.Fatalf("write custom config.yaml: %v", err)
		}
	} else {
		dsn := fmt.Sprintf("file:%s/remote-signer.db?_journal_mode=WAL&_busy_timeout=5000", home)
		// Pin keystore and HD-wallet directories under the per-test home so
		// signer create/HD wallet create do not leak across parallel tests.
		// Without this the daemon defaults to ./data/{keystores,hd-wallets}
		// relative to its working directory and quickly hits the per-key
		// resource limits.
		yaml := fmt.Sprintf(
			"server:\n  host: 127.0.0.1\n  port: %d\n  tls:\n    enabled: false\n"+
				"database:\n  dsn: %q\n"+
				"logger:\n  level: info\n"+
				"chains:\n  evm:\n    enabled: true\n    keystore_dir: %q\n    hd_wallet_dir: %q\n",
			port, dsn,
			filepath.Join(home, "keystores"),
			filepath.Join(home, "hd-wallets"),
		)
		if err := os.WriteFile(configPath, []byte(yaml), 0600); err != nil {
			t.Fatalf("write default config.yaml: %v", err)
		}
	}

	args := []string{"server", "start", "-config", configPath}

	cmd := exec.Command(binaryPath, args...)
	cmd.Env = append(os.Environ(), "REMOTE_SIGNER_HOME="+home)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// New process group so we can send SIGTERM cleanly on cleanup.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatalf("start daemon: %v", err)
	}

	d := &daemon{t: t, home: home, configPath: configPath, port: port, cmd: cmd, logFile: logFile}
	t.Cleanup(d.stop)

	if !cfg.skipReady {
		if err := d.waitReady(15 * time.Second); err != nil {
			d.dumpLog()
			t.Fatalf("daemon never became ready on %s: %v", d.url(), err)
		}
	}
	return d
}

// url returns the daemon's base HTTP URL.
func (d *daemon) url() string { return fmt.Sprintf("http://127.0.0.1:%d", d.port) }

// adminKeyPath returns the bootstrap admin private-key path. Exists once the
// daemon has finished booting. Mirrors homepath.AdminKeyPaths() — the
// bootstrap keypair lives under the apikeys/ subdirectory so every API
// credential file shares a single location.
func (d *daemon) adminKeyPath() string {
	return filepath.Join(d.home, "apikeys", "admin.key.priv")
}

// waitReady polls /health every 100ms until it returns 200 or the deadline
// elapses.
func (d *daemon) waitReady(deadline time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	client := &http.Client{Timeout: 500 * time.Millisecond}
	url := d.url() + "/health"
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// stop sends SIGTERM to the daemon's process group, waits for exit, and
// closes the log file. Idempotent; safe to call from t.Cleanup.
func (d *daemon) stop() {
	if d.cmd != nil && d.cmd.Process != nil {
		_ = syscall.Kill(-d.cmd.Process.Pid, syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = d.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-d.cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		d.cmd = nil
	}
	if d.logFile != nil {
		d.logFile.Close()
		d.logFile = nil
	}
}

// wait blocks until the daemon exits and returns its ExitError. Useful for
// tests that expect startup to fail.
func (d *daemon) wait() error {
	if d.cmd == nil {
		return nil
	}
	err := d.cmd.Wait()
	d.cmd = nil
	if d.logFile != nil {
		d.logFile.Close()
		d.logFile = nil
	}
	return err
}

// dumpLog writes the daemon log to the test output. Called on failure.
// The log lives in the parent of the home dir (the tempdir root) so it is
// not nuked by the daemon's own home-dir creation path; see startDaemon.
func (d *daemon) dumpLog() {
	d.t.Helper()
	logPath := filepath.Join(filepath.Dir(d.home), "daemon.log")
	data, err := os.ReadFile(logPath)
	if err != nil {
		d.t.Logf("daemon log unreadable: %v", err)
		return
	}
	d.t.Logf("--- daemon log %s ---\n%s\n--- end ---", logPath, data)
}

// cli runs the binary one-shot (no daemon) with the given args. Stdin is
// empty; stdout and stderr are returned along with the exit error.
func cli(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

// runCLI invokes the binary against the daemon with admin credentials
// pre-filled. Use for `settings`, `api-key`, etc.
func (d *daemon) runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	full := append([]string{},
		"--url", d.url(),
		"--api-key-id", "admin",
		"--api-key-file", d.adminKeyPath(),
	)
	full = append(full, args...)
	return cli(t, full...)
}

// runCLIJSON is runCLI plus a JSON decode of stdout. Fails the test on
// non-zero exit OR malformed JSON.
func (d *daemon) runCLIJSON(t *testing.T, out interface{}, args ...string) {
	t.Helper()
	stdout, stderr, err := d.runCLI(t, args...)
	if err != nil {
		t.Fatalf("cli %v: %v\nstdout: %s\nstderr: %s", args, err, stdout, stderr)
	}
	if err := json.Unmarshal([]byte(stdout), out); err != nil {
		t.Fatalf("decode JSON from %v: %v\nstdout: %s", args, err, stdout)
	}
}

// restartInHome relaunches the daemon against an existing home directory
// (admin keys + DB preserved). The config file is reused from configPath;
// callers pass the same path they handed startDaemon. Used to verify
// idempotent-bootstrap behaviour on the second launch.
func restartInHome(t *testing.T, home, configPath string, port int) *daemon {
	t.Helper()
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("expected existing config.yaml at %s: %v", configPath, err)
	}
	logFile, err := os.OpenFile(filepath.Join(filepath.Dir(configPath), "daemon.log"), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		t.Fatalf("reopen log: %v", err)
	}
	cmd := exec.Command(binaryPath, "server", "start", "-config", configPath)
	cmd.Env = append(os.Environ(), "REMOTE_SIGNER_HOME="+home)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatalf("relaunch: %v", err)
	}
	d := &daemon{t: t, home: home, configPath: configPath, port: port, cmd: cmd, logFile: logFile}
	t.Cleanup(d.stop)
	if err := d.waitReady(15 * time.Second); err != nil {
		d.dumpLog()
		t.Fatalf("daemon never became ready on %s after restart: %v", d.url(), err)
	}
	return d
}
