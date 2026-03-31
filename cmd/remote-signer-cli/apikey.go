package main

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/remote-signer/pkg/client/apikeys"
)

// --- api-key parent ---

var apiKeyCmd = &cobra.Command{
	Use:     "api-key",
	Aliases: []string{"apikey"},
	Short:   "Manage API keys (admin only)",
}

// --- api-key list ---

var apiKeyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List API keys",
	RunE:  runAPIKeyList,
}

var (
	flagAPIKeyListSource  string
	flagAPIKeyListEnabled string
	flagAPIKeyListLimit   int
	flagAPIKeyListOffset  int
)

func runAPIKeyList(cmd *cobra.Command, args []string) error {
	c, err := newClientFromFlags(cmd)
	if err != nil {
		return err
	}

	filter := &apikeys.ListFilter{
		Limit:  flagAPIKeyListLimit,
		Offset: flagAPIKeyListOffset,
	}
	if flagAPIKeyListSource != "" {
		filter.Source = flagAPIKeyListSource
	}
	if flagAPIKeyListEnabled != "" {
		b, err := strconv.ParseBool(flagAPIKeyListEnabled)
		if err != nil {
			return fmt.Errorf("invalid --enabled value %q: %w", flagAPIKeyListEnabled, err)
		}
		filter.Enabled = &b
	}

	resp, err := c.APIKeys.List(cmd.Context(), filter)
	if err != nil {
		return fmt.Errorf("list api keys: %w", err)
	}

	if flagOutputFormat == "json" {
		return printJSON(resp)
	}

	fmt.Printf("Total: %d\n", resp.Total)
	printTable(
		[]string{"ID", "NAME", "SOURCE", "ROLE", "ENABLED", "RATE_LIMIT"},
		func() [][]string {
			rows := make([][]string, len(resp.Keys))
			for i, k := range resp.Keys {
				rows[i] = []string{
					k.ID, k.Name, k.Source, k.Role,
					strconv.FormatBool(k.Enabled),
					strconv.Itoa(k.RateLimit),
				}
			}
			return rows
		}(),
	)
	return nil
}

// --- api-key get ---

var apiKeyGetCmd = &cobra.Command{
	Use:   "get <key-id>",
	Short: "Get API key details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		key, err := c.APIKeys.Get(cmd.Context(), args[0])
		if err != nil {
			return fmt.Errorf("get api key: %w", err)
		}
		return printJSON(key)
	},
}

// --- api-key create ---

var apiKeyCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new API key (admin only)",
	RunE:  runAPIKeyCreate,
}

var (
	flagAPIKeyCreateID        string
	flagAPIKeyCreateName      string
	flagAPIKeyCreatePublicKey string
	flagAPIKeyCreateRole      string
	flagAPIKeyCreateRateLimit int
)

func runAPIKeyCreate(cmd *cobra.Command, args []string) error {
	c, err := newClientFromFlags(cmd)
	if err != nil {
		return err
	}

	req := &apikeys.CreateRequest{
		ID:        flagAPIKeyCreateID,
		Name:      flagAPIKeyCreateName,
		PublicKey: flagAPIKeyCreatePublicKey,
		Role:      flagAPIKeyCreateRole,
		RateLimit: flagAPIKeyCreateRateLimit,
	}

	key, err := c.APIKeys.Create(cmd.Context(), req)
	if err != nil {
		return fmt.Errorf("create api key: %w", err)
	}
	return printJSON(key)
}

// --- api-key update ---

var apiKeyUpdateCmd = &cobra.Command{
	Use:   "update <key-id>",
	Short: "Update an API key (admin only, API-sourced keys only)",
	Args:  cobra.ExactArgs(1),
	RunE:  runAPIKeyUpdate,
}

var (
	flagAPIKeyUpdateName      string
	flagAPIKeyUpdateRole      string
	flagAPIKeyUpdateEnabled   string
	flagAPIKeyUpdateRateLimit int
)

func runAPIKeyUpdate(cmd *cobra.Command, args []string) error {
	c, err := newClientFromFlags(cmd)
	if err != nil {
		return err
	}

	req := &apikeys.UpdateRequest{}

	if cmd.Flags().Changed("name") {
		req.Name = &flagAPIKeyUpdateName
	}
	if cmd.Flags().Changed("role") {
		req.Role = &flagAPIKeyUpdateRole
	}
	if cmd.Flags().Changed("enabled") {
		b, err := strconv.ParseBool(flagAPIKeyUpdateEnabled)
		if err != nil {
			return fmt.Errorf("invalid --enabled value %q: %w", flagAPIKeyUpdateEnabled, err)
		}
		req.Enabled = &b
	}
	if cmd.Flags().Changed("rate-limit") {
		req.RateLimit = &flagAPIKeyUpdateRateLimit
	}

	key, err := c.APIKeys.Update(cmd.Context(), args[0], req)
	if err != nil {
		return fmt.Errorf("update api key: %w", err)
	}

	if flagOutputFormat == "json" {
		return printJSON(key)
	}

	fmt.Printf("API key %s updated\n", key.ID)
	return nil
}

// --- api-key delete ---

var apiKeyDeleteCmd = &cobra.Command{
	Use:   "delete <key-id>",
	Short: "Delete an API key (admin only, API-sourced keys only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			return err
		}
		if err := c.APIKeys.Delete(cmd.Context(), args[0]); err != nil {
			return fmt.Errorf("delete api key: %w", err)
		}
		fmt.Printf("API key %s deleted\n", args[0])
		return nil
	},
}

// --- registration ---

func init() {
	// list flags
	apiKeyListCmd.Flags().StringVar(&flagAPIKeyListSource, "source", "", "Filter by source (config, api)")
	apiKeyListCmd.Flags().StringVar(&flagAPIKeyListEnabled, "enabled", "", "Filter by enabled (true/false)")
	apiKeyListCmd.Flags().IntVar(&flagAPIKeyListLimit, "limit", 50, "Max results to return")
	apiKeyListCmd.Flags().IntVar(&flagAPIKeyListOffset, "offset", 0, "Offset for pagination")

	// create flags
	apiKeyCreateCmd.Flags().StringVar(&flagAPIKeyCreateID, "id", "", "API key ID")
	if err := apiKeyCreateCmd.MarkFlagRequired("id"); err != nil {
		panic(err)
	}
	apiKeyCreateCmd.Flags().StringVar(&flagAPIKeyCreateName, "name", "", "API key name")
	if err := apiKeyCreateCmd.MarkFlagRequired("name"); err != nil {
		panic(err)
	}
	apiKeyCreateCmd.Flags().StringVar(&flagAPIKeyCreatePublicKey, "public-key", "", "Ed25519 public key (base64 or hex)")
	if err := apiKeyCreateCmd.MarkFlagRequired("public-key"); err != nil {
		panic(err)
	}
	apiKeyCreateCmd.Flags().StringVar(&flagAPIKeyCreateRole, "role", "dev", "Role: admin, dev, agent, strategy")
	apiKeyCreateCmd.Flags().IntVar(&flagAPIKeyCreateRateLimit, "rate-limit", 0, "Rate limit (requests per second)")

	// update flags
	apiKeyUpdateCmd.Flags().StringVar(&flagAPIKeyUpdateName, "name", "", "New name")
	apiKeyUpdateCmd.Flags().StringVar(&flagAPIKeyUpdateRole, "role", "", "New role: admin, dev, agent, strategy")
	apiKeyUpdateCmd.Flags().StringVar(&flagAPIKeyUpdateEnabled, "enabled", "", "Enable or disable (true/false)")
	apiKeyUpdateCmd.Flags().IntVar(&flagAPIKeyUpdateRateLimit, "rate-limit", 0, "New rate limit")

	apiKeyCmd.AddCommand(apiKeyListCmd)
	apiKeyCmd.AddCommand(apiKeyGetCmd)
	apiKeyCmd.AddCommand(apiKeyCreateCmd)
	apiKeyCmd.AddCommand(apiKeyUpdateCmd)
	apiKeyCmd.AddCommand(apiKeyDeleteCmd)
}
