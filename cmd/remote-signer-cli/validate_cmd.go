package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

// Binary name for the rules validator (avoids clashing with other tools in PATH).
const validateRulesBinaryName = "remote-signer-validate-rules"

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Run rule validation (executes " + validateRulesBinaryName + " binary)",
	Long:  "Executes the " + validateRulesBinaryName + " binary with the same flags. Pass flags after the subcommand, e.g. -config config.yaml",
	RunE:  runValidateCmd,
}

func runValidateCmd(cmd *cobra.Command, args []string) error {
	return runValidate(args)
}

// runValidate exec's the remote-signer-validate-rules binary with the given args (forwarded flags).
// It looks for the binary in the same directory as the current executable, then in PATH.
func runValidate(args []string) error {
	bin, err := findBinary(validateRulesBinaryName)
	if err != nil {
		return fmt.Errorf("%s not found: %w (install in the same directory as remote-signer-cli or in PATH)", validateRulesBinaryName, err)
	}
	c := exec.Command(bin, args...) // #nosec G204 G702 -- bin from findBinary (same dir or PATH), args forwarded to validator CLI
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			os.Exit(exit.ExitCode())
		}
		return err
	}
	return nil
}

// findBinary looks for name in the same directory as the current executable, then in PATH.
func findBinary(name string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return exec.LookPath(name)
	}
	sameDir := filepath.Join(filepath.Dir(self), name)
	if info, err := os.Stat(sameDir); err == nil && !info.IsDir() && info.Mode()&0111 != 0 {
		return sameDir, nil
	}
	return exec.LookPath(name)
}
