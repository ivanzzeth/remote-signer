// smoke-test exercises the v0.3 templates + presets + registry surface
// against a live local daemon. Reads the agent api key from
// ~/.remote-signer/apikeys/tmp/agent.key.priv and hits every endpoint
// the UI uses, validating the new wire shape (chain_type, template_ids,
// variable options, etc.) by going through a raw HTTP transport so the
// Go SDK's pre-R9 typed shapes don't constrain what we can check.
//
// Run: go run ./cmd/smoke-test
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const baseURL = "http://localhost:8548"

func main() {
	home, _ := os.UserHomeDir()
	keyBytes, err := os.ReadFile(home + "/.remote-signer/apikeys/tmp/agent.key.priv")
	if err != nil {
		die("read agent key: %v", err)
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		die("decode PEM: no block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		die("parse PKCS8: %v", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		die("not an ed25519 key: %T", parsed)
	}
	tx := &transport{apiKeyID: "agent", priv: priv, http: &http.Client{Timeout: 15 * time.Second}}

	pass, fail := 0, 0
	step := func(name string, err error) {
		if err != nil {
			fmt.Printf("FAIL  %s\n        %v\n", name, err)
			fail++
			return
		}
		fmt.Printf("PASS  %s\n", name)
		pass++
	}

	// 1. Templates list — count + sample EVM row's chain_type
	var tList struct {
		Templates []map[string]any `json:"templates"`
		Total     int              `json:"total"`
	}
	err = tx.do(http.MethodGet, "/api/v1/templates", nil, &tList)
	step("GET /api/v1/templates", err)
	if err == nil {
		fmt.Printf("        → %d templates\n", tList.Total)
		var sampleEVM, sampleOff map[string]any
		for _, t := range tList.Templates {
			id, _ := t["id"].(string)
			ct, _ := t["chain_type"].(string)
			if sampleEVM == nil && strings.HasPrefix(id, "evm/") && ct == "evm" {
				sampleEVM = t
			}
			if sampleOff == nil && !strings.Contains(id, "/") {
				sampleOff = t
			}
		}
		if sampleEVM != nil {
			fmt.Printf("        sample evm: id=%v chain_type=%v mode=%v\n",
				sampleEVM["id"], sampleEVM["chain_type"], sampleEVM["mode"])
		} else {
			fmt.Printf("WARN  no evm/* template with chain_type=evm found\n")
		}
		if sampleOff != nil {
			fmt.Printf("        sample off-chain: id=%v chain_type=%v\n",
				sampleOff["id"], sampleOff["chain_type"])
		}
	}

	// 2. Templates.Get evm/erc20 (slash-ID round-trip)
	var t1 map[string]any
	err = tx.do(http.MethodGet, "/api/v1/templates/evm%2Ferc20", nil, &t1)
	step("GET /api/v1/templates/evm%2Ferc20", err)
	if err == nil {
		fmt.Printf("        → name=%v chain_type=%v mode=%v\n",
			t1["name"], t1["chain_type"], t1["mode"])
		// variables[]: check for the new fields
		if vs, ok := t1["variables"].([]any); ok && len(vs) > 0 {
			if v, ok := vs[0].(map[string]any); ok {
				fmt.Printf("        var[0]: name=%v type=%v required=%v\n",
					v["name"], v["type"], v["required"])
			}
		}
	}

	// 3. Templates.Get off-chain
	var stoa map[string]any
	err = tx.do(http.MethodGet, "/api/v1/templates/sign_type_allowlist", nil, &stoa)
	step("GET /api/v1/templates/sign_type_allowlist", err)
	if err == nil {
		ct, _ := stoa["chain_type"].(string)
		fmt.Printf("        → chain_type=%q (should be empty for off-chain)\n", ct)
		if ct != "" {
			fmt.Printf("WARN  expected empty chain_type for off-chain template\n")
		}
	}

	// 4. Presets list — check template_ids field surfaced
	var pList struct {
		Presets []map[string]any `json:"presets"`
	}
	err = tx.do(http.MethodGet, "/api/v1/presets", nil, &pList)
	step("GET /api/v1/presets", err)
	if err == nil {
		fmt.Printf("        → %d presets\n", len(pList.Presets))
		for _, p := range pList.Presets[:min(2, len(pList.Presets))] {
			fmt.Printf("        sample: id=%v name=%v template_ids=%v\n",
				p["id"], p["name"], p["template_ids"])
		}
	}

	// 5. Presets.Get evm/erc20 — slash-ID + joined variable defs (R8 401 fix)
	var p1 map[string]any
	err = tx.do(http.MethodGet, "/api/v1/presets/evm%2Ferc20", nil, &p1)
	step("GET /api/v1/presets/evm%2Ferc20", err)
	if err == nil {
		fmt.Printf("        → name=%v chain=%v/%v template_ids=%v\n",
			p1["name"], p1["chain_type"], p1["chain_id"], p1["template_ids"])
		if vs, ok := p1["variables"].([]any); ok {
			var emptyType, withType int
			for _, raw := range vs {
				v, _ := raw.(map[string]any)
				if v == nil {
					continue
				}
				if t, _ := v["type"].(string); t == "" {
					emptyType++
				} else {
					withType++
				}
			}
			fmt.Printf("        variables: %d with type, %d without\n", withType, emptyType)
			if emptyType > 0 {
				fmt.Printf("WARN  %d preset variables lack a type (template join failed?)\n", emptyType)
			}
		}
	}

	// 6. Preset detail for evm/usdc (had ${budget_period} apply bug)
	var p2 map[string]any
	err = tx.do(http.MethodGet, "/api/v1/presets/evm%2Fusdc", nil, &p2)
	step("GET /api/v1/presets/evm%2Fusdc", err)
	if err == nil {
		fmt.Printf("        → name=%v\n", p2["name"])
	}

	// 7. Registry refresh — second pass should skip everything
	var rr map[string]any
	err = tx.do(http.MethodPost, "/api/v1/registry/refresh", nil, &rr)
	step("POST /api/v1/registry/refresh", err)
	if err == nil {
		if t, ok := rr["templates"].(map[string]any); ok {
			fmt.Printf("        → templates: changed=%v skipped=%v deleted=%v\n",
				t["changed"], t["skipped"], t["deleted"])
		}
		if p, ok := rr["presets"].(map[string]any); ok {
			fmt.Printf("        → presets:   changed=%v skipped=%v deleted=%v\n",
				p["changed"], p["skipped"], p["deleted"])
		}
	}

	fmt.Printf("\n--- %d passed, %d failed ---\n", pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

// transport is a minimal ed25519-signed request helper. Defined inline
// in this smoke-test because pkg/client's transport is internal-only.
type transport struct {
	apiKeyID string
	priv     ed25519.PrivateKey
	http     *http.Client
}

func (t *transport) do(method, path string, body []byte, out any) error {
	ts := time.Now().UnixMilli()
	nonce := newNonce()
	// Server-side format (see pkg/client/internal/transport/auth.go):
	//   {timestamp}|{nonce}|{method}|{path}|{sha256(body)}
	// Signature goes out base64-encoded.
	bodyHash := sha256.Sum256(body)
	msg := fmt.Sprintf("%d|%s|%s|%s|%x", ts, nonce, method, path, bodyHash)
	sig := ed25519.Sign(t.priv, []byte(msg))

	req, err := http.NewRequestWithContext(context.Background(), method, baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key-ID", t.apiKeyID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(sig))

	resp, err := t.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	if out != nil && len(bodyBytes) > 0 {
		if err := json.Unmarshal(bodyBytes, out); err != nil {
			return fmt.Errorf("decode: %w (body=%s)", err, string(bodyBytes))
		}
	}
	return nil
}

func newNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
