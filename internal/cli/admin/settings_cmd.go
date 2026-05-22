package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// `settings` operates on the daemon's runtime-mutable configuration store
// (system_settings table). All operations hit the admin HTTP API and require
// the admin role; the local config.yaml is the bootstrap minimum and these
// commands edit everything beyond it.

var settingsCmd = &cobra.Command{
	Use:   "settings",
	Short: "Inspect and update runtime configuration (admin only)",
	Long: `Runtime configuration lives in the system_settings table on the daemon and
is read through /api/v1/admin/settings/:group. Available groups today:
security. PR7c/d add notify-channels, evm.foundry, evm.simulation, and
others as those subsystems migrate off the YAML config.`,
}

var settingsShowCmd = &cobra.Command{
	Use:   "show <group>",
	Short: "Print the current snapshot for a settings group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		body, err := c.Settings.Get(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("get %s: %w", args[0], err)
		}
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, body, "", "  "); err != nil {
			os.Stdout.Write(body)
			fmt.Println()
			return nil
		}
		os.Stdout.Write(pretty.Bytes())
		fmt.Println()
		return nil
	},
}


var settingsSetCmd = &cobra.Command{
	Use:   "set <group> <key=value> [<key=value> ...]",
	Short: "Patch one or more fields of a settings group",
	Long: `Reads the current snapshot, applies the given key=value overrides, and PUTs
the result back to the daemon. Values are parsed as JSON if they look like
JSON literals (true/false, numbers, quoted strings, [arrays]); otherwise
treated as raw strings. Nested keys use dot notation, e.g.

  remote-signer settings set security ip_rate_limit=500 \
      manual_approval_enabled=true \
      'ip_whitelist={"enabled":true,"allowed_ips":["10.0.0.0/8"]}'`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		group := args[0]
		assignments := args[1:]
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		current, err := c.Settings.Get(cmd.Context(), group)
		if err != nil {
			return fmt.Errorf("get %s: %w", group, err)
		}
		var snap map[string]any
		if err := json.Unmarshal(current, &snap); err != nil {
			return fmt.Errorf("decode current snapshot: %w", err)
		}
		for _, a := range assignments {
			if err := applyAssignment(snap, a); err != nil {
				return err
			}
		}
		patch, err := json.Marshal(snap)
		if err != nil {
			return fmt.Errorf("encode patch: %w", err)
		}
		out, err := c.Settings.Put(cmd.Context(), group, patch)
		if err != nil {
			return fmt.Errorf("put %s: %w", group, err)
		}
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, out, "", "  "); err == nil {
			os.Stdout.Write(pretty.Bytes())
		} else {
			os.Stdout.Write(out)
		}
		fmt.Println()
		return nil
	},
}

// applyAssignment turns key=value into a mutation on snap. Values that parse
// as JSON are applied as-is (preserving numbers/bools/objects); anything else
// becomes a string. Dotted keys like "ip_whitelist.enabled" or
// "channels.slack" descend into nested maps so callers can target a single
// field without rewriting the entire snapshot.
func applyAssignment(snap map[string]any, s string) error {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return fmt.Errorf("expected key=value, got %q", s)
	}
	key, raw := s[:eq], s[eq+1:]
	value := parseValue(raw)
	path := strings.Split(key, ".")
	return setNested(snap, path, value)
}

// setNested writes value at path inside obj, creating intermediate map[string]any
// nodes as needed. If an intermediate node already exists and is not a map,
// the call fails so the user gets a clear error instead of silently nuking
// a typed value.
func setNested(obj map[string]any, path []string, value any) error {
	for i, segment := range path {
		if i == len(path)-1 {
			obj[segment] = value
			return nil
		}
		existing, ok := obj[segment]
		if !ok || existing == nil {
			next := make(map[string]any)
			obj[segment] = next
			obj = next
			continue
		}
		next, isMap := existing.(map[string]any)
		if !isMap {
			return fmt.Errorf("cannot descend into %q: existing value is %T, not an object", segment, existing)
		}
		obj = next
	}
	return nil
}

func parseValue(raw string) any {
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err == nil {
		return v
	}
	if b, e := strconv.ParseBool(raw); e == nil {
		return b
	}
	if n, e := strconv.ParseInt(raw, 10, 64); e == nil {
		return n
	}
	return raw
}

func init() {
	settingsCmd.AddCommand(settingsShowCmd)
	settingsCmd.AddCommand(settingsSetCmd)
}
