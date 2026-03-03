package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

const tuiBinaryName = "remote-signer-tui"

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch TUI (executes " + tuiBinaryName + " binary)",
	Long:  "Executes the " + tuiBinaryName + " binary with forwarded args, e.g. -api-key-id admin -api-key-file data/admin_private.pem -url http://localhost:8548",
	RunE:  runTUICmd,
}

func runTUICmd(cmd *cobra.Command, args []string) error {
	return runTUI(args)
}

// runTUI exec's the remote-signer-tui binary with the given args.
// It looks for the binary in the same directory as the current executable, then in PATH.
func runTUI(args []string) error {
	bin, err := findBinary(tuiBinaryName)
	if err != nil {
		return fmt.Errorf("find %s: %w (install it in the same directory as remote-signer-cli or in PATH)", tuiBinaryName, err)
	}
	c := exec.Command(bin, args...) // #nosec G204 G702 -- bin from findBinary (same dir or PATH), args forwarded to TUI CLI
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
