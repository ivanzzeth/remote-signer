package homepath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHomeRespectsEnv(t *testing.T) {
	t.Setenv("REMOTE_SIGNER_HOME", "/tmp/rs-test-home")
	got, err := Home()
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/rs-test-home" {
		t.Errorf("Home() = %q, want %q", got, "/tmp/rs-test-home")
	}
}

func TestEnsureHomeCreatesWith0700(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, ".remote-signer")
	t.Setenv("REMOTE_SIGNER_HOME", target)
	got, err := EnsureHome()
	if err != nil {
		t.Fatal(err)
	}
	if got != target {
		t.Errorf("EnsureHome() = %q, want %q", got, target)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("home dir mode = %o, want 0700", perm)
	}
}

func TestResolveConfigPathFlagWins(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)
	flagPath := filepath.Join(tmp, "custom.yaml")
	if err := os.WriteFile(flagPath, []byte("server:\n  port: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, exists, err := ResolveConfigPath(flagPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != flagPath || !exists {
		t.Errorf("ResolveConfigPath(%q) = %q, exists=%v; want %q, true", flagPath, got, exists, flagPath)
	}
}

func TestResolveConfigPathFallsBackToHome(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)
	t.Setenv("REMOTE_SIGNER_CONFIG", "")

	// Use a sandbox cwd so the project-local ./config.yaml fallback never matches.
	wd := filepath.Join(tmp, "wd")
	if err := os.MkdirAll(wd, 0700); err != nil {
		t.Fatal(err)
	}
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	if err := os.Chdir(wd); err != nil {
		t.Fatal(err)
	}

	got, exists, err := ResolveConfigPath("")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(tmp, "config.yaml")
	if got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
	if exists {
		t.Errorf("exists = true, want false for non-existent home config")
	}
}

func TestWriteDefaultConfigIsValidYAML(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)
	path := filepath.Join(tmp, "config.yaml")
	if err := WriteDefaultConfig(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("config.yaml is empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("config.yaml mode = %o, want 0600", perm)
	}
}
