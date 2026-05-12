package homepath

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteDefaultConfig writes a minimal but functional config.yaml to path with
// 0600 permissions. The defaults match the zero-config story: SQLite under the
// home dir, listen on :8548, no TLS, info-level logging, chains.evm enabled.
// Anything not represented here is filled by config.setDefaults() at load time.
//
// Phase 3 will progressively trim this template as more knobs migrate into the
// system_settings table; for now it stays full enough that the server boots
// without any further user input.
func WriteDefaultConfig(path string) error {
	dsn, err := DefaultSQLiteDSN()
	if err != nil {
		return err
	}
	home, err := Home()
	if err != nil {
		return err
	}
	content := fmt.Sprintf(defaultConfigTemplate,
		dsn,
		filepath.Join(home, "keystores"),
		filepath.Join(home, "hd-wallets"),
	)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0600)
}

const defaultConfigTemplate = `# remote-signer default configuration.
# Auto-generated on first launch; tune as needed and restart.
#
# For multi-instance deployments behind PostgreSQL, set the DATABASE_DSN env
# var (e.g. postgres://...) — it overrides the SQLite DSN below.

server:
  host: 0.0.0.0
  port: 8548
  read_timeout: 30s
  write_timeout: 30s
  tls:
    enabled: false

database:
  dsn: "%s"

logger:
  level: info
  pretty: true

chains:
  evm:
    enabled: true
    keystore_dir: "%s"
    hd_wallet_dir: "%s"
`
