package homepath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAPIKeysDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)
	got, err := APIKeysDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(tmp, "apikeys")
	if got != want {
		t.Errorf("APIKeysDir() = %q, want %q", got, want)
	}
}

func TestSignerKeystoresDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)
	got, err := SignerKeystoresDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(tmp, "keystores")
	if got != want {
		t.Errorf("SignerKeystoresDir() = %q, want %q", got, want)
	}
}

func TestAdminKeyPaths(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)
	priv, pub, err := AdminKeyPaths()
	if err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(tmp, "apikeys")
	if filepath.Dir(priv) != wantDir || filepath.Dir(pub) != wantDir {
		t.Errorf("AdminKeyPaths() dirs = %q, %q; want %q", filepath.Dir(priv), filepath.Dir(pub), wantDir)
	}
	if filepath.Base(priv) != "admin.key.priv" {
		t.Errorf("priv key filename = %q, want admin.key.priv", filepath.Base(priv))
	}
	if filepath.Base(pub) != "admin.key.pub" {
		t.Errorf("pub key filename = %q, want admin.key.pub", filepath.Base(pub))
	}
}

func TestAdminKeystorePath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)
	got, err := AdminKeystorePath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(tmp, "apikeys", "admin.keystore.json")
	if got != want {
		t.Errorf("AdminKeystorePath() = %q, want %q", got, want)
	}
}

func TestAgentKeyPaths(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)
	priv, pub, err := AgentKeyPaths()
	if err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(tmp, "apikeys")
	if filepath.Dir(priv) != wantDir || filepath.Dir(pub) != wantDir {
		t.Errorf("AgentKeyPaths() dirs = %q, %q; want %q", filepath.Dir(priv), filepath.Dir(pub), wantDir)
	}
	if filepath.Base(priv) != "agent.key.priv" {
		t.Errorf("priv key filename = %q, want agent.key.priv", filepath.Base(priv))
	}
	if filepath.Base(pub) != "agent.key.pub" {
		t.Errorf("pub key filename = %q, want agent.key.pub", filepath.Base(pub))
	}
}

func TestConfigPath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)
	got, err := ConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(tmp, "config.yaml")
	if got != want {
		t.Errorf("ConfigPath() = %q, want %q", got, want)
	}
}

func TestSQLitePath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)
	got, err := SQLitePath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(tmp, "remote-signer.db")
	if got != want {
		t.Errorf("SQLitePath() = %q, want %q", got, want)
	}
}

func TestDefaultSQLiteDSN(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)
	got, err := DefaultSQLiteDSN()
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := "file:" + filepath.Join(tmp, "remote-signer.db") + "?"
	if got[:len(wantPrefix)] != wantPrefix {
		t.Errorf("DefaultSQLiteDSN() = %q, want prefix %q", got, wantPrefix)
	}
}

func TestHome_FallsBackToUserHome(t *testing.T) {
	// Ensure env var is not set, then test the fallback
	t.Setenv("REMOTE_SIGNER_HOME", "")
	got, err := Home()
	if err != nil {
		t.Fatal(err)
	}
	userHome, _ := os.UserHomeDir()
	want := filepath.Join(userHome, ".remote-signer")
	if got != want {
		t.Errorf("Home() = %q, want %q", got, want)
	}
}

func TestEnsureHome_AlreadyExists(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, ".remote-signer")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REMOTE_SIGNER_HOME", target)
	got, err := EnsureHome()
	if err != nil {
		t.Fatal(err)
	}
	if got != target {
		t.Errorf("EnsureHome() = %q, want %q", got, target)
	}
}

func TestResolveConfigPath_EnvVarExists(t *testing.T) {
	tmp := t.TempDir()
	envPath := filepath.Join(tmp, "env-config.yaml")
	if err := os.WriteFile(envPath, []byte("key: val\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REMOTE_SIGNER_CONFIG", envPath)
	t.Setenv("REMOTE_SIGNER_HOME", tmp)

	got, exists, err := ResolveConfigPath("")
	if err != nil {
		t.Fatal(err)
	}
	if got != envPath || !exists {
		t.Errorf("ResolveConfigPath('') = %q, exists=%v; want %q, true", got, exists, envPath)
	}
}

func TestResolveConfigPath_EnvVarMissing(t *testing.T) {
	tmp := t.TempDir()
	envPath := filepath.Join(tmp, "missing.yaml")
	t.Setenv("REMOTE_SIGNER_CONFIG", envPath)
	t.Setenv("REMOTE_SIGNER_HOME", tmp)

	got, exists, err := ResolveConfigPath("")
	if err != nil {
		t.Fatal(err)
	}
	if got != envPath || exists {
		t.Errorf("ResolveConfigPath('') = %q, exists=%v; want %q, false", got, exists, envPath)
	}
}

func TestResolveConfigPath_HomeConfigExists(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)
	homeConfig := filepath.Join(tmp, "config.yaml")
	if err := os.WriteFile(homeConfig, []byte("key: val\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got, exists, err := ResolveConfigPath("")
	if err != nil {
		t.Fatal(err)
	}
	if got != homeConfig || !exists {
		t.Errorf("ResolveConfigPath('') = %q, exists=%v; want %q, true", got, exists, homeConfig)
	}
}

func TestResolveConfigPath_LocalConfigExists(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)

	// Create local config.yaml in cwd
	localPath := filepath.Join(tmp, "config.yaml")
	if err := os.WriteFile(localPath, []byte("key: val\n"), 0600); err != nil {
		t.Fatal(err)
	}
	prev, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	got, exists, err := ResolveConfigPath("")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.Abs("./config.yaml")
	if got != want || !exists {
		t.Errorf("ResolveConfigPath('') = %q, exists=%v; want %q, true", got, exists, want)
	}
}

func TestResolveConfigPath_NothingExists(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)

	prev, _ := os.Getwd()
	wd := filepath.Join(tmp, "subdir")
	if err := os.MkdirAll(wd, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(wd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	got, exists, err := ResolveConfigPath("")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(tmp, "config.yaml")
	if got != want || exists {
		t.Errorf("ResolveConfigPath('') = %q, exists=%v; want %q, false", got, exists, want)
	}
}

func TestWriteDefaultConfig(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)
	path := filepath.Join(tmp, "custom", "config.yaml")
	if err := WriteDefaultConfig(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("config is empty")
	}
}
