package simulation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultRegistryBaseURL     = "https://api.4byte.sourcify.dev/signature-database/v1"
	defaultRegistryHTTPTimeout = 5 * time.Second
)

// SignatureRegistry resolves 4-byte selectors and 32-byte event topic0 hashes
// via the Sourcify/OpenChain signature database with an in-memory TTL cache.
type SignatureRegistry struct {
	baseURL string
	client  *http.Client
	ttl     time.Duration

	mu        sync.RWMutex
	funcSigs  map[string]cacheEntry
	eventSigs map[string]cacheEntry
}

type cacheEntry struct {
	names []string
	at    time.Time
}

// registryLookupResponse matches api.4byte.sourcify.dev lookup JSON.
type registryLookupResponse struct {
	OK     bool `json:"ok"`
	Result struct {
		Function map[string][]registrySig `json:"function"`
		Event    map[string][]registrySig `json:"event"`
	} `json:"result"`
}

type registrySig struct {
	Name                string `json:"name"`
	Filtered            bool   `json:"filtered"`
	HasVerifiedContract bool   `json:"hasVerifiedContract"`
}

var defaultRegistry = NewSignatureRegistry(defaultRegistryBaseURL, 24*time.Hour)

// GlobalSignatureRegistry returns the process-wide registry used by simulation.
func GlobalSignatureRegistry() *SignatureRegistry {
	return defaultRegistry
}

// NewSignatureRegistry creates a registry client. Pass baseURL="" to disable HTTP
// lookups (cache + Seed* only — useful in tests).
func NewSignatureRegistry(baseURL string, ttl time.Duration) *SignatureRegistry {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &SignatureRegistry{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		client:  &http.Client{Timeout: defaultRegistryHTTPTimeout},
		ttl:     ttl,
		funcSigs:  make(map[string]cacheEntry),
		eventSigs: make(map[string]cacheEntry),
	}
}

// SeedFunction preloads the function/error selector cache (tests, offline).
func (r *SignatureRegistry) SeedFunction(hexSelector string, names ...string) {
	if r == nil {
		return
	}
	key := normalizeLookupKey(hexSelector)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.funcSigs[key] = cacheEntry{names: append([]string(nil), names...), at: time.Now()}
}

// SeedEvent preloads the event topic0 cache (tests, offline).
func (r *SignatureRegistry) SeedEvent(topic0 string, names ...string) {
	if r == nil {
		return
	}
	key := normalizeLookupKey(topic0)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eventSigs[key] = cacheEntry{names: append([]string(nil), names...), at: time.Now()}
}

// LookupFunctions returns candidate text signatures for 4-byte selectors.
func (r *SignatureRegistry) LookupFunctions(ctx context.Context, selectors ...string) map[string][]string {
	if r == nil || len(selectors) == 0 {
		return nil
	}
	return r.lookup(ctx, "function", selectors, r.funcSigs)
}

// LookupEvents returns candidate text signatures for 32-byte event topic0 hashes.
func (r *SignatureRegistry) LookupEvents(ctx context.Context, topic0s ...string) map[string][]string {
	if r == nil || len(topic0s) == 0 {
		return nil
	}
	return r.lookup(ctx, "event", topic0s, r.eventSigs)
}

func (r *SignatureRegistry) lookup(
	ctx context.Context,
	kind string,
	keys []string,
	store map[string]cacheEntry,
) map[string][]string {
	normalized := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		nk := normalizeLookupKey(k)
		if nk == "" {
			continue
		}
		if _, ok := seen[nk]; ok {
			continue
		}
		seen[nk] = struct{}{}
		normalized = append(normalized, nk)
	}
	if len(normalized) == 0 {
		return nil
	}

	out := make(map[string][]string, len(normalized))
	var missing []string
	now := time.Now()

	r.mu.RLock()
	for _, k := range normalized {
		if ent, ok := store[k]; ok && now.Sub(ent.at) < r.ttl {
			if len(ent.names) > 0 {
				out[k] = append([]string(nil), ent.names...)
			}
			continue
		}
		missing = append(missing, k)
	}
	r.mu.RUnlock()

	if len(missing) > 0 && r.baseURL != "" {
		fetched, err := r.fetch(ctx, kind, missing)
		if err == nil {
			r.mu.Lock()
			for _, k := range missing {
				names := fetched[k]
				store[k] = cacheEntry{names: names, at: time.Now()}
				if len(names) > 0 {
					out[k] = append([]string(nil), names...)
				}
			}
			r.mu.Unlock()
		}
	}

	return out
}

func (r *SignatureRegistry) fetch(ctx context.Context, kind string, keys []string) (map[string][]string, error) {
	if r.client == nil {
		return nil, fmt.Errorf("registry client not configured")
	}
	queryKeys := make([]string, len(keys))
	for i, k := range keys {
		nk := normalizeLookupKey(k)
		if nk == "" {
			continue
		}
		queryKeys[i] = "0x" + nk
	}
	q := url.Values{}
	q.Set(kind, strings.Join(queryKeys, ","))
	endpoint := r.baseURL + "/lookup?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry HTTP %d", resp.StatusCode)
	}

	var parsed registryLookupResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	if !parsed.OK {
		return nil, fmt.Errorf("registry lookup not ok")
	}

	var bucket map[string][]registrySig
	switch kind {
	case "function":
		bucket = parsed.Result.Function
	case "event":
		bucket = parsed.Result.Event
	default:
		return nil, fmt.Errorf("unknown kind %q", kind)
	}

	out := make(map[string][]string, len(keys))
	for _, k := range keys {
		nk := normalizeLookupKey(k)
		entries := registryBucketEntries(bucket, nk)
		if len(entries) == 0 {
			out[nk] = nil
			continue
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			name := strings.TrimSpace(e.Name)
			if name != "" {
				names = append(names, name)
			}
		}
		out[nk] = names
	}
	return out, nil
}

// registryBucketEntries reads lookup results keyed with or without a 0x prefix.
func registryBucketEntries(bucket map[string][]registrySig, nk string) []registrySig {
	if entries := bucket[nk]; len(entries) > 0 {
		return entries
	}
	return bucket["0x"+nk]
}

func normalizeLookupKey(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	return strings.TrimPrefix(s, "0x")
}
