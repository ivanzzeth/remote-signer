package blocklist

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// Source fetches addresses from an external data source.
type Source interface {
	// Name returns a human-readable name for logging.
	Name() string
	// Fetch returns a set of checksummed Ethereum addresses.
	Fetch(ctx context.Context) ([]string, error)
}

// SourceConfig defines a blocklist source in configuration.
type SourceConfig struct {
	Name     string `yaml:"name" json:"name"`
	Type     string `yaml:"type" json:"type"`         // "url_text" or "url_json"
	URL      string `yaml:"url" json:"url"`
	JSONPath string `yaml:"json_path" json:"json_path"` // for url_json: dot-separated key path to address array (e.g. "addresses" or "data.addresses")
}

// NewSource creates a Source from config.
func NewSource(cfg SourceConfig, httpClient *http.Client) (Source, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("source %q: url is required", cfg.Name)
	}
	if !strings.HasPrefix(cfg.URL, "https://") && !strings.HasPrefix(cfg.URL, "http://") {
		return nil, fmt.Errorf("source %q: url must start with http:// or https:// (got %q)", cfg.Name, cfg.URL)
	}
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	switch cfg.Type {
	case "url_text":
		return &urlTextSource{name: cfg.Name, url: cfg.URL, client: httpClient}, nil
	case "url_json":
		if cfg.JSONPath == "" {
			return nil, fmt.Errorf("source %q: json_path is required for url_json type", cfg.Name)
		}
		return &urlJSONSource{name: cfg.Name, url: cfg.URL, jsonPath: cfg.JSONPath, client: httpClient}, nil
	default:
		return nil, fmt.Errorf("source %q: unsupported type %q (must be url_text or url_json)", cfg.Name, cfg.Type)
	}
}

// urlTextSource fetches addresses from a plain text URL (one address per line).
type urlTextSource struct {
	name   string
	url    string
	client *http.Client
}

func (s *urlTextSource) Name() string { return s.name }

func (s *urlTextSource) Fetch(ctx context.Context) ([]string, error) {
	body, err := httpGet(ctx, s.client, s.url)
	if err != nil {
		return nil, fmt.Errorf("source %q: %w", s.name, err)
	}
	return parseTextAddresses(body), nil
}

// urlJSONSource fetches addresses from a JSON URL using a dot-path to locate the array.
type urlJSONSource struct {
	name     string
	url      string
	jsonPath string
	client   *http.Client
}

func (s *urlJSONSource) Name() string { return s.name }

func (s *urlJSONSource) Fetch(ctx context.Context) ([]string, error) {
	body, err := httpGet(ctx, s.client, s.url)
	if err != nil {
		return nil, fmt.Errorf("source %q: %w", s.name, err)
	}
	return extractJSONAddresses(body, s.jsonPath, s.name)
}

// httpGet fetches URL content with context support and retry on 5xx errors.
func httpGet(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	const maxRetries = 3
	backoff := 1 * time.Second

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2 // exponential backoff: 1s, 2s, 4s
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("User-Agent", "remote-signer-blocklist/1.0")

		resp, err := client.Do(req)
		if err != nil {
			if attempt < maxRetries-1 {
				continue // retry on network error
			}
			return nil, fmt.Errorf("fetch %s: %w", url, err)
		}

		if resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			// Limit response body to 10MB to prevent abuse.
			const maxBody = 10 * 1024 * 1024
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
			if err != nil {
				return nil, fmt.Errorf("read body: %w", err)
			}
			return body, nil
		}

		_ = resp.Body.Close() // Ignore close error on non-200 response body

		// Retry on 5xx (server errors), fail immediately on 4xx (client errors)
		if resp.StatusCode >= 500 && attempt < maxRetries-1 {
			continue
		}
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}

	return nil, fmt.Errorf("fetch %s: max retries exceeded", url)
}

// parseTextAddresses parses one-address-per-line text, skipping empty lines and # comments.
func parseTextAddresses(data []byte) []string {
	var addrs []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if common.IsHexAddress(line) {
			addrs = append(addrs, common.HexToAddress(line).Hex())
		}
	}
	return addrs
}

// extractJSONAddresses extracts addresses from JSON using a dot-separated key path.
// Supports paths like "addresses", "data.addresses", or direct top-level array.
func extractJSONAddresses(data []byte, jsonPath string, sourceName string) ([]string, error) {
	var raw interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("source %q: invalid JSON: %w", sourceName, err)
	}

	// Navigate the dot path to find the array.
	current := raw
	if jsonPath != "" {
		for _, key := range strings.Split(jsonPath, ".") {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			m, ok := current.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("source %q: json_path %q: expected object at key %q", sourceName, jsonPath, key)
			}
			current, ok = m[key]
			if !ok {
				return nil, fmt.Errorf("source %q: json_path %q: key %q not found", sourceName, jsonPath, key)
			}
		}
	}

	// Extract addresses from the array.
	arr, ok := current.([]interface{})
	if !ok {
		return nil, fmt.Errorf("source %q: json_path %q: expected array, got %T", sourceName, jsonPath, current)
	}

	var addrs []string
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if common.IsHexAddress(s) {
			addrs = append(addrs, common.HexToAddress(s).Hex())
		}
	}
	return addrs, nil
}
