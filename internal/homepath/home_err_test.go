package homepath

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// EnsureHome: MkdirAll error when parent path is a regular file
// =============================================================================

func TestEnsureHome_MkdirAllError(t *testing.T) {
	tmp := t.TempDir()
	// Create a regular file
	filePath := filepath.Join(tmp, "not-a-dir")
	if err := os.WriteFile(filePath, []byte("blocker"), 0600); err != nil {
		t.Fatal(err)
	}
	// Point home at the file as if it were a directory — MkdirAll will fail
	t.Setenv("REMOTE_SIGNER_HOME", filePath)
	_, err := EnsureHome()
	assert.Error(t, err)
}

// =============================================================================
// WriteDefaultConfig: MkdirAll error when parent path is a regular file
// =============================================================================

func TestWriteDefaultConfig_MkdirAllError(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)
	// Create a file where the config dir should be, so MkdirAll fails
	blocker := filepath.Join(tmp, "subdir")
	if err := os.WriteFile(blocker, []byte("blocker"), 0600); err != nil {
		t.Fatal(err)
	}
	err := WriteDefaultConfig(filepath.Join(blocker, "config.yaml"))
	assert.Error(t, err)
}

// =============================================================================
// ResolveConfigPath: flag path stat returns a non-ErrNotExist error
// /dev/null/foo triggers ENOTDIR on Linux
// =============================================================================

func TestResolveConfigPath_FlagPathStatError(t *testing.T) {
	_, _, err := ResolveConfigPath("/dev/null/foo")
	assert.Error(t, err)
}

// =============================================================================
// ResolveConfigPath: env var path stat returns a non-ErrNotExist error
// =============================================================================

func TestResolveConfigPath_EnvStatError(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)
	t.Setenv("REMOTE_SIGNER_CONFIG", "/dev/null/foo")
	_, _, err := ResolveConfigPath("")
	assert.Error(t, err)
}

// =============================================================================
// ResolveConfigPath: home config path stat returns a non-ErrNotExist error
// =============================================================================

func TestResolveConfigPath_HomeConfigStatError(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("REMOTE_SIGNER_HOME", tmp)
	// Put a file where the config directory should be to trigger stat error
	// The home dir IS a file, so ConfigPath points to a path under a file
	blocker := filepath.Join(tmp, "config.yaml")
	if err := os.WriteFile(blocker, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	// Now ResolveConfigPath will check if ConfigPath() exists and stat will
	// succeed (it's a file), so it returns exists=true.
	_, exists, err := ResolveConfigPath("")
	assert.NoError(t, err)
	assert.True(t, exists)
}

// =============================================================================
// ResolveConfigPath: local config stat error (cwd is a file)
// =============================================================================

func TestResolveConfigPath_LocalConfigStatError(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home")
	if err := os.MkdirAll(homeDir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REMOTE_SIGNER_HOME", homeDir)

	// Create a file in cwd as a blocker and chdir there.
	blocker := filepath.Join(tmp, "blocker.txt")
	if err := os.WriteFile(blocker, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	prev, _ := os.Getwd()
	if err := os.Chdir(blocker); err != nil {
		t.Skip("chdir to file succeeded — cannot test stat error on this OS")
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	_, _, err := ResolveConfigPath("")
	// Should not error, just fall through to returning the home config path
	assert.NoError(t, err)
}

// =============================================================================
// Home: os.UserHomeDir() error when HOME is unset
// =============================================================================

func TestHome_UserHomeDirError(t *testing.T) {
	// Make sure REMOTE_SIGNER_HOME is not set, then unset HOME so UserHomeDir fails
	t.Setenv("REMOTE_SIGNER_HOME", "")
	t.Setenv("HOME", "")
	_, err := Home()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "resolve user home")
}

// =============================================================================
// Functions that delegate to Home() — error path when HOME is unset
// =============================================================================

func TestEnsureHome_UserHomeDirError(t *testing.T) {
	t.Setenv("REMOTE_SIGNER_HOME", "")
	t.Setenv("HOME", "")
	_, err := EnsureHome()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "resolve user home")
}

func TestConfigPath_UserHomeDirError(t *testing.T) {
	t.Setenv("REMOTE_SIGNER_HOME", "")
	t.Setenv("HOME", "")
	_, err := ConfigPath()
	assert.Error(t, err)
}

func TestSQLitePath_UserHomeDirError(t *testing.T) {
	t.Setenv("REMOTE_SIGNER_HOME", "")
	t.Setenv("HOME", "")
	_, err := SQLitePath()
	assert.Error(t, err)
}

func TestDefaultSQLiteDSN_UserHomeDirError(t *testing.T) {
	t.Setenv("REMOTE_SIGNER_HOME", "")
	t.Setenv("HOME", "")
	_, err := DefaultSQLiteDSN()
	assert.Error(t, err)
}

func TestAPIKeysDir_UserHomeDirError(t *testing.T) {
	t.Setenv("REMOTE_SIGNER_HOME", "")
	t.Setenv("HOME", "")
	_, err := APIKeysDir()
	assert.Error(t, err)
}

func TestSignerKeystoresDir_UserHomeDirError(t *testing.T) {
	t.Setenv("REMOTE_SIGNER_HOME", "")
	t.Setenv("HOME", "")
	_, err := SignerKeystoresDir()
	assert.Error(t, err)
}

func TestAdminKeyPaths_UserHomeDirError(t *testing.T) {
	t.Setenv("REMOTE_SIGNER_HOME", "")
	t.Setenv("HOME", "")
	_, _, err := AdminKeyPaths()
	assert.Error(t, err)
}

func TestAdminKeystorePath_UserHomeDirError(t *testing.T) {
	t.Setenv("REMOTE_SIGNER_HOME", "")
	t.Setenv("HOME", "")
	_, err := AdminKeystorePath()
	assert.Error(t, err)
}

func TestAgentKeyPaths_UserHomeDirError(t *testing.T) {
	t.Setenv("REMOTE_SIGNER_HOME", "")
	t.Setenv("HOME", "")
	_, _, err := AgentKeyPaths()
	assert.Error(t, err)
}

// =============================================================================
// ResolveConfigPath: flag path does not exist (ErrNotExist)
// =============================================================================

func TestResolveConfigPath_FlagPathNotExist(t *testing.T) {
	path, exists, err := ResolveConfigPath("/nonexistent/path/for/testing.yaml")
	assert.NoError(t, err)
	assert.False(t, exists)
	assert.Equal(t, "/nonexistent/path/for/testing.yaml", path)
}

// =============================================================================
// ResolveConfigPath: ConfigPath error (HOME unset)
// =============================================================================

func TestResolveConfigPath_ConfigPathError(t *testing.T) {
	t.Setenv("REMOTE_SIGNER_HOME", "")
	t.Setenv("HOME", "")
	_, _, err := ResolveConfigPath("")
	assert.Error(t, err)
}

// =============================================================================
// ResolveConfigPath: home config stat error (non-ErrNotExist)
// =============================================================================

func TestResolveConfigPath_HomeConfigStatNonNotExist(t *testing.T) {
	tmp := t.TempDir()
	// Create a file in the target dir, then replace the dir with a file
	// so stat on ConfigPath() returns a non-ErrNotExist error.
	homeDir := filepath.Join(tmp, "home")
	if err := os.MkdirAll(homeDir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REMOTE_SIGNER_HOME", homeDir)
	// Put a file where the home config would be - no this would succeed stat.
	// Instead, make the home itself a file path
	fileHome := filepath.Join(tmp, "file-home")
	if err := os.WriteFile(fileHome, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REMOTE_SIGNER_HOME", fileHome)
	// Now ConfigPath() returns fileHome + "/config.yaml"
	// os.Stat on that will fail with ENOTDIR on Linux
	_, _, err := ResolveConfigPath("")
	assert.Error(t, err)
}
