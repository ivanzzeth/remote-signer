package admin

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/homepath"
)

// `config` groups read-only inspection commands for the local config file.
// These do not contact the server — they just resolve and parse what the
// daemon would see on startup.

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Inspect the local config.yaml (no server contact)",
}

var (
	flagConfigShowPath string
)

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Print the resolved config.yaml path",
	Long: `Resolves the config.yaml path the daemon would load, in the same order:
-config flag → $REMOTE_SIGNER_CONFIG → ~/.remote-signer/config.yaml →
./config.yaml. Prints two columns: the path and whether the file currently
exists. Useful for tooling and for diagnosing "which config is in effect".`,
	RunE: func(_ *cobra.Command, _ []string) error {
		path, exists, err := homepath.ResolveConfigPath(flagConfigShowPath)
		if err != nil {
			return err
		}
		state := "missing (would be auto-generated on first server start)"
		if exists {
			state = "exists"
		}
		fmt.Println(path)
		fmt.Fprintln(os.Stderr, state)
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print the effective config (after defaults are applied)",
	Long: `Loads the resolved config.yaml, applies the same defaults the daemon would,
and prints the result as YAML to stdout. The output reflects what the daemon
would actually use — handy when troubleshooting why a setting behaves the
way it does.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		path, exists, err := homepath.ResolveConfigPath(flagConfigShowPath)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("config file %s does not exist; run `remote-signer` once to auto-generate it, or pass --config", path)
		}
		cfg, err := config.Load(path)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		out, err := yaml.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("marshal config: %w", err)
		}
		fmt.Fprintf(os.Stderr, "# loaded from: %s\n", path)
		os.Stdout.Write(out)
		return nil
	},
}

func init() {
	configPathCmd.Flags().StringVar(&flagConfigShowPath, "config", "", "Explicit config path (skips the default resolution chain)")
	configShowCmd.Flags().StringVar(&flagConfigShowPath, "config", "", "Explicit config path (skips the default resolution chain)")
	configCmd.AddCommand(configPathCmd)
	configCmd.AddCommand(configShowCmd)
}
