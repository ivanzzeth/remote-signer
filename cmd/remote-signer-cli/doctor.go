package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose local setup: version, URL reachability, TLS paths, key files (no secrets printed)",
	RunE:  runDoctor,
}

type doctorReport struct {
	OK      bool              `json:"ok"`
	Version string            `json:"version"`
	Checks  []doctorCheckItem `json:"checks"`
}

type doctorCheckItem struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail,omitempty"`
	Warning bool   `json:"warning,omitempty"`
}

func runDoctor(cmd *cobra.Command, args []string) error {
	report := doctorReport{
		Version: version,
		Checks:  nil,
	}

	report.Checks = append(report.Checks, doctorCheckItem{Name: "cli_version", OK: true, Detail: version})

	// URL / health (no auth)
	url := flagURL
	if url == "" {
		url = "https://localhost:8548"
	}
	report.Checks = append(report.Checks, checkHealthEndpoint(url))

	// TLS files — existence only
	if flagTLSCA != "" {
		report.Checks = append(report.Checks, checkFileReadable("tls_ca", flagTLSCA))
	}
	if flagTLSCert != "" {
		report.Checks = append(report.Checks, checkFileReadable("tls_client_cert", flagTLSCert))
	}
	if flagTLSKey != "" {
		report.Checks = append(report.Checks, checkFileReadable("tls_client_key", flagTLSKey))
	}

	// API key material paths (never print contents)
	if flagAPIKeyFile != "" {
		report.Checks = append(report.Checks, checkFileReadable("api_key_file", flagAPIKeyFile))
	}
	if flagAPIKeyKeystore != "" {
		report.Checks = append(report.Checks, checkFileReadable("api_key_keystore", flagAPIKeyKeystore))
	}

	// Optional authenticated health if client can be built
	if flagAPIKeyID != "" && (flagAPIKeyFile != "" || flagAPIKeyKeystore != "") {
		c, err := newClientFromFlags(cmd)
		if err != nil {
			report.Checks = append(report.Checks, doctorCheckItem{Name: "authenticated_client", OK: false, Detail: err.Error()})
		} else {
			ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
			defer cancel()
			h, err := c.Health(ctx)
			if err != nil {
				report.Checks = append(report.Checks, doctorCheckItem{Name: "api_health_json", OK: false, Detail: err.Error()})
			} else {
				detail := h.Status
				if h.Version != "" {
					detail = fmt.Sprintf("status=%s server_version=%s", h.Status, h.Version)
				}
				report.Checks = append(report.Checks, doctorCheckItem{Name: "api_health_json", OK: true, Detail: detail})
			}
		}
	} else {
		report.Checks = append(report.Checks, doctorCheckItem{
			Name:    "authenticated_client",
			OK:      true,
			Warning: true,
			Detail:  "skipped (--api-key-id and key file/keystore not fully set)",
		})
	}

	report.OK = true
	for _, c := range report.Checks {
		if !c.OK {
			report.OK = false
			break
		}
	}

	if strings.EqualFold(flagOutputFormat, "json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	fmt.Printf("remote-signer-cli doctor — %s\n\n", version)
	for _, c := range report.Checks {
		st := "ok"
		if !c.OK {
			st = "FAIL"
		} else if c.Warning {
			st = "warn"
		}
		line := fmt.Sprintf("[%s] %s", st, c.Name)
		if c.Detail != "" {
			line += ": " + c.Detail
		}
		fmt.Println(line)
	}
	if !report.OK {
		return fmt.Errorf("one or more checks failed")
	}
	return nil
}

func checkHealthEndpoint(base string) doctorCheckItem {
	u := strings.TrimRight(base, "/") + "/health"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doctorCheckItem{Name: "health_endpoint", OK: false, Detail: err.Error()}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// distinguish DNS / connection refused
		return doctorCheckItem{Name: "health_endpoint", OK: false, Detail: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return doctorCheckItem{Name: "health_endpoint", OK: false, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	return doctorCheckItem{Name: "health_endpoint", OK: true, Detail: u + " reachable"}
}

func checkFileReadable(name, path string) doctorCheckItem {
	st, err := os.Stat(path)
	if err != nil {
		return doctorCheckItem{Name: name, OK: false, Detail: err.Error()}
	}
	if st.IsDir() {
		return doctorCheckItem{Name: name, OK: false, Detail: "path is a directory"}
	}
	f, err := os.Open(path) // #nosec G304
	if err != nil {
		return doctorCheckItem{Name: name, OK: false, Detail: err.Error()}
	}
	_, readErr := f.Read(make([]byte, 1))
	closeErr := f.Close()
	if closeErr != nil {
		return doctorCheckItem{Name: name, OK: false, Detail: closeErr.Error()}
	}
	if readErr != nil && readErr != io.EOF {
		return doctorCheckItem{Name: name, OK: false, Detail: readErr.Error()}
	}
	return doctorCheckItem{Name: name, OK: true, Detail: "readable"}
}
