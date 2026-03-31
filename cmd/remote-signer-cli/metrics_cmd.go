package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "GET /metrics (Prometheus text; only --url required, no API auth)",
	RunE: func(cmd *cobra.Command, args []string) error {
		base := flagURL
		if base == "" {
			base = "https://localhost:8548"
		}
		u := strings.TrimRight(base, "/") + "/metrics"
		resp, err := http.Get(u) // #nosec G107 -- user-provided base URL from CLI
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("metrics: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		text := string(body)
		if strings.EqualFold(flagOutputFormat, "json") {
			type out struct {
				PrometheusText string `json:"prometheus_text"`
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out{PrometheusText: text})
		}
		fmt.Print(text)
		return nil
	},
}
