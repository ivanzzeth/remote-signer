package evm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

const (
	rpcCallTimeout     = 5 * time.Second
	rpcMaxCallsPerEval = 10

	// Global rate limiter defaults
	rpcGlobalRatePerSec  = 50  // max RPC calls per second across all evaluations
	rpcGlobalBurstSize   = 100 // token bucket burst

	// Circuit breaker defaults
	circuitBreakerThreshold = 10 // consecutive errors to trip
	circuitBreakerResetTime = 30 * time.Second
)

// blockedRPCMethods are write methods that must never be called from the JS sandbox.
var blockedRPCMethods = map[string]bool{
	"eth_sendTransaction":    true,
	"eth_sendRawTransaction": true,
	"eth_sign":               true,
	"personal_sign":          true,
	"eth_signTransaction":    true,
	"eth_signTypedData":      true,
	"eth_signTypedData_v4":   true,
}

// allowedRPCMethods are the only methods the JS sandbox may invoke.
var allowedRPCMethods = map[string]bool{
	"eth_call":                true,
	"eth_getCode":             true,
	"eth_getTransactionCount": true,
}

// chainIDPattern validates that chain IDs are numeric only (SSRF prevention).
var chainIDPattern = regexp.MustCompile(`^[0-9]+$`)

// RPCGatewayConfig holds configuration for the EVM RPC gateway used by JS rules.
type RPCGatewayConfig struct {
	BaseURL  string        `yaml:"base_url" json:"base_url"`
	APIKey   string        `yaml:"api_key,omitempty" json:"api_key,omitempty"`
	CacheTTL time.Duration `yaml:"cache_ttl" json:"cache_ttl"`
}

// tokenBucket implements a simple token-bucket rate limiter.
type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	maxBurst float64
	rate     float64 // tokens per second
	lastTime time.Time
}

func newTokenBucket(ratePerSec, burst float64) *tokenBucket {
	return &tokenBucket{
		tokens:   burst,
		maxBurst: burst,
		rate:     ratePerSec,
		lastTime: time.Now(),
	}
}

// allow tries to consume one token. Returns false if rate limited.
func (tb *tokenBucket) allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(tb.lastTime).Seconds()
	tb.lastTime = now
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.maxBurst {
		tb.tokens = tb.maxBurst
	}
	if tb.tokens < 1 {
		return false
	}
	tb.tokens--
	return true
}

// circuitBreaker tracks consecutive errors and trips open to prevent cascading failures.
type circuitBreaker struct {
	mu              sync.Mutex
	consecutiveErrs int
	threshold       int
	trippedAt       time.Time
	resetTime       time.Duration
}

func newCircuitBreaker(threshold int, resetTime time.Duration) *circuitBreaker {
	return &circuitBreaker{
		threshold: threshold,
		resetTime: resetTime,
	}
}

// isOpen returns true if the circuit is tripped (too many consecutive errors).
func (cb *circuitBreaker) isOpen() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.consecutiveErrs < cb.threshold {
		return false
	}
	// Auto-reset after resetTime
	if time.Since(cb.trippedAt) > cb.resetTime {
		cb.consecutiveErrs = 0
		return false
	}
	return true
}

// recordSuccess resets the error count.
func (cb *circuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.consecutiveErrs = 0
}

// recordError increments the error count and may trip the circuit.
func (cb *circuitBreaker) recordError() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.consecutiveErrs++
	if cb.consecutiveErrs >= cb.threshold {
		cb.trippedAt = time.Now()
	}
}

// RPCProvider performs read-only JSON-RPC calls via the evm-gateway.
type RPCProvider struct {
	baseURL string
	apiKey  string
	client  *http.Client
	limiter *tokenBucket
	breaker *circuitBreaker
}

// NewRPCProvider creates a new RPCProvider. baseURL must not be empty.
// SECURITY: The HTTP client disables redirects (SSRF prevention) and enforces TLS verification.
func NewRPCProvider(baseURL, apiKey string) (*RPCProvider, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, fmt.Errorf("rpc gateway base_url is required")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &RPCProvider{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		apiKey:  strings.TrimSpace(apiKey),
		client: &http.Client{
			Timeout:   rpcCallTimeout,
			Transport: transport,
			// SECURITY: Disable redirects to prevent SSRF via 3xx responses
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("rpc provider does not follow redirects")
			},
		},
		limiter: newTokenBucket(rpcGlobalRatePerSec, rpcGlobalBurstSize),
		breaker: newCircuitBreaker(circuitBreakerThreshold, circuitBreakerResetTime),
	}, nil
}

// rpcURL builds the full RPC endpoint URL for a given chain ID.
// SECURITY: chainID is validated as numeric-only before reaching this method.
func (p *RPCProvider) rpcURL(chainID string) string {
	url := p.baseURL + "/" + chainID
	if p.apiKey != "" {
		url += "/api_key/" + p.apiKey
	}
	return url
}

type jsonRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *jsonRPCError   `json:"error,omitempty"`
	ID      int             `json:"id"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ValidateChainID validates that a chain ID is a positive integer string (SSRF prevention).
func ValidateChainID(chainID string) error {
	chainID = strings.TrimSpace(chainID)
	if chainID == "" {
		return fmt.Errorf("chain_id is required")
	}
	if !chainIDPattern.MatchString(chainID) {
		return fmt.Errorf("chain_id must be numeric: %q", chainID)
	}
	// Ensure it's a valid positive integer (not just "0000")
	n, err := strconv.ParseUint(chainID, 10, 64)
	if err != nil || n == 0 {
		return fmt.Errorf("chain_id must be a positive integer: %q", chainID)
	}
	return nil
}

// ValidateHexData validates that data is a valid hex string with 0x prefix.
func ValidateHexData(data string) error {
	if !strings.HasPrefix(data, "0x") && !strings.HasPrefix(data, "0X") {
		return fmt.Errorf("data must start with 0x")
	}
	raw := data[2:]
	if len(raw)%2 != 0 {
		return fmt.Errorf("data hex must have even length")
	}
	if _, err := hex.DecodeString(raw); err != nil {
		return fmt.Errorf("data contains invalid hex: %w", err)
	}
	return nil
}

// ValidateEthAddress validates a 20-byte Ethereum address (0x + 40 hex chars).
func ValidateEthAddress(addr string) error {
	if !common.IsHexAddress(addr) {
		return fmt.Errorf("invalid address: %s", addr)
	}
	return nil
}

// Call performs eth_call and returns the hex result.
func (p *RPCProvider) Call(ctx context.Context, chainID, to, data string) (string, error) {
	if err := ValidateChainID(chainID); err != nil {
		return "", fmt.Errorf("call: %w", err)
	}
	if err := ValidateEthAddress(to); err != nil {
		return "", fmt.Errorf("call: %w", err)
	}
	if err := ValidateHexData(data); err != nil {
		return "", fmt.Errorf("call: %w", err)
	}
	params := []interface{}{
		map[string]string{"to": to, "data": data},
		"latest",
	}
	return p.doRPC(ctx, chainID, "eth_call", params)
}

// GetCode performs eth_getCode and returns the hex bytecode.
func (p *RPCProvider) GetCode(ctx context.Context, chainID, address string) (string, error) {
	if err := ValidateChainID(chainID); err != nil {
		return "", fmt.Errorf("getCode: %w", err)
	}
	if err := ValidateEthAddress(address); err != nil {
		return "", fmt.Errorf("getCode: %w", err)
	}
	params := []interface{}{address, "latest"}
	return p.doRPC(ctx, chainID, "eth_getCode", params)
}

// GetTransactionCount performs eth_getTransactionCount and returns the nonce.
func (p *RPCProvider) GetTransactionCount(ctx context.Context, chainID, address string) (uint64, error) {
	if err := ValidateChainID(chainID); err != nil {
		return 0, fmt.Errorf("getTransactionCount: %w", err)
	}
	if err := ValidateEthAddress(address); err != nil {
		return 0, fmt.Errorf("getTransactionCount: %w", err)
	}
	params := []interface{}{address, "pending"}
	result, err := p.doRPC(ctx, chainID, "eth_getTransactionCount", params)
	if err != nil {
		return 0, err
	}
	// Parse hex result
	result = strings.TrimPrefix(result, "0x")
	n, err := strconv.ParseUint(result, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid nonce hex %q: %w", result, err)
	}
	return n, nil
}

// SendRawTransaction broadcasts a signed transaction via eth_sendRawTransaction.
// This method bypasses the allowedRPCMethods check since it is not called from JS sandbox.
func (p *RPCProvider) SendRawTransaction(ctx context.Context, chainID, signedTxHex string) (string, error) {
	if err := ValidateChainID(chainID); err != nil {
		return "", fmt.Errorf("sendRawTransaction: %w", err)
	}
	params := []interface{}{signedTxHex}
	return p.doRPCUnchecked(ctx, chainID, "eth_sendRawTransaction", params)
}

// GetTransactionReceipt fetches the receipt of a transaction by hash.
// Returns empty string result if the tx is not yet mined.
func (p *RPCProvider) GetTransactionReceipt(ctx context.Context, chainID, txHash string) (json.RawMessage, error) {
	if err := ValidateChainID(chainID); err != nil {
		return nil, fmt.Errorf("getTransactionReceipt: %w", err)
	}
	params := []interface{}{txHash}
	return p.doRPCRaw(ctx, chainID, "eth_getTransactionReceipt", params)
}

// QueryAllowance queries on-chain ERC20 allowance(owner, spender) for a token contract.
// Returns the current allowance as *big.Int.
func (p *RPCProvider) QueryAllowance(ctx context.Context, chainID, token, owner, spender string) (*big.Int, error) {
	// allowance(address,address) selector = 0xdd62ed3e
	// Encode: selector + padded owner + padded spender
	ownerPadded := fmt.Sprintf("%064s", strings.TrimPrefix(strings.ToLower(owner), "0x"))
	spenderPadded := fmt.Sprintf("%064s", strings.TrimPrefix(strings.ToLower(spender), "0x"))
	data := "0xdd62ed3e" + ownerPadded + spenderPadded

	params := []interface{}{
		map[string]string{"to": token, "data": data},
		"latest",
	}
	result, err := p.doRPCUnchecked(ctx, chainID, "eth_call", params)
	if err != nil {
		return nil, fmt.Errorf("allowance query failed: %w", err)
	}

	// Parse hex result
	result = strings.TrimPrefix(result, "0x")
	if result == "" {
		return big.NewInt(0), nil
	}
	val := new(big.Int)
	if _, ok := val.SetString(result, 16); !ok {
		return nil, fmt.Errorf("invalid allowance response: %s", result)
	}
	return val, nil
}

// doRPCUnchecked performs a JSON-RPC call without allowedRPCMethods check.
// Used for server-side operations (broadcast) that are not exposed to JS sandbox.
func (p *RPCProvider) doRPCUnchecked(ctx context.Context, chainID, method string, params []interface{}) (string, error) {
	// SECURITY: Check circuit breaker
	if p.breaker.isOpen() {
		return "", fmt.Errorf("rpc circuit breaker open: too many consecutive errors")
	}
	if !p.limiter.allow() {
		return "", fmt.Errorf("rpc global rate limit exceeded")
	}

	reqBody, err := json.Marshal(jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	})
	if err != nil {
		return "", fmt.Errorf("marshal rpc request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, rpcCallTimeout)
	defer cancel()

	url := p.rpcURL(chainID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.breaker.recordError()
		return "", fmt.Errorf("rpc request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		p.breaker.recordError()
		return "", fmt.Errorf("read rpc response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		p.breaker.recordError()
		return "", fmt.Errorf("rpc returned status %d: %s", resp.StatusCode, string(body))
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		p.breaker.recordError()
		return "", fmt.Errorf("unmarshal rpc response: %w", err)
	}
	if rpcResp.Error != nil {
		p.breaker.recordError()
		return "", fmt.Errorf("rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	var result string
	if err := json.Unmarshal(rpcResp.Result, &result); err != nil {
		p.breaker.recordError()
		return "", fmt.Errorf("unmarshal rpc result: %w", err)
	}

	p.breaker.recordSuccess()
	return result, nil
}

// doRPCRaw performs a JSON-RPC call and returns the raw result JSON.
func (p *RPCProvider) doRPCRaw(ctx context.Context, chainID, method string, params []interface{}) (json.RawMessage, error) {
	if p.breaker.isOpen() {
		return nil, fmt.Errorf("rpc circuit breaker open: too many consecutive errors")
	}
	if !p.limiter.allow() {
		return nil, fmt.Errorf("rpc global rate limit exceeded")
	}

	reqBody, err := json.Marshal(jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal rpc request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, rpcCallTimeout)
	defer cancel()

	url := p.rpcURL(chainID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.breaker.recordError()
		return nil, fmt.Errorf("rpc request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		p.breaker.recordError()
		return nil, fmt.Errorf("read rpc response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		p.breaker.recordError()
		return nil, fmt.Errorf("rpc returned status %d: %s", resp.StatusCode, string(body))
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		p.breaker.recordError()
		return nil, fmt.Errorf("unmarshal rpc response: %w", err)
	}
	if rpcResp.Error != nil {
		p.breaker.recordError()
		return nil, fmt.Errorf("rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	p.breaker.recordSuccess()
	return rpcResp.Result, nil
}

func (p *RPCProvider) doRPC(ctx context.Context, chainID, method string, params []interface{}) (string, error) {
	if blockedRPCMethods[method] {
		return "", fmt.Errorf("rpc method %q is blocked", method)
	}
	if !allowedRPCMethods[method] {
		return "", fmt.Errorf("rpc method %q is not allowed", method)
	}

	// SECURITY: Check circuit breaker — if too many consecutive errors, fail fast
	if p.breaker.isOpen() {
		return "", fmt.Errorf("rpc circuit breaker open: too many consecutive errors, using cached data only")
	}

	// SECURITY: Global rate limit across all evaluations
	if !p.limiter.allow() {
		return "", fmt.Errorf("rpc global rate limit exceeded")
	}

	reqBody, err := json.Marshal(jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	})
	if err != nil {
		return "", fmt.Errorf("marshal rpc request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, rpcCallTimeout)
	defer cancel()

	url := p.rpcURL(chainID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		p.breaker.recordError()
		return "", fmt.Errorf("rpc request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		p.breaker.recordError()
		return "", fmt.Errorf("read rpc response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		p.breaker.recordError()
		return "", fmt.Errorf("rpc returned status %d: %s", resp.StatusCode, string(body))
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		p.breaker.recordError()
		return "", fmt.Errorf("unmarshal rpc response: %w", err)
	}
	if rpcResp.Error != nil {
		p.breaker.recordError()
		return "", fmt.Errorf("rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	var result string
	if err := json.Unmarshal(rpcResp.Result, &result); err != nil {
		p.breaker.recordError()
		return "", fmt.Errorf("unmarshal rpc result: %w", err)
	}

	p.breaker.recordSuccess()
	return result, nil
}

// rpcMaxTotalTime is the maximum cumulative time allowed for all RPC calls within a single evaluation.
const rpcMaxTotalTime = 15 * time.Second

// RPCCallCounter tracks RPC calls per evaluation to enforce rate limits and cumulative duration.
type RPCCallCounter struct {
	count         int
	max           int
	cumulativeDur time.Duration
	maxTotalTime  time.Duration
}

// NewRPCCallCounter creates a counter with the given max calls per evaluation.
func NewRPCCallCounter(max int) *RPCCallCounter {
	if max <= 0 {
		max = rpcMaxCallsPerEval
	}
	return &RPCCallCounter{max: max, maxTotalTime: rpcMaxTotalTime}
}

// Increment increments the counter and returns an error if the limit is exceeded.
func (c *RPCCallCounter) Increment() error {
	c.count++
	if c.count > c.max {
		return fmt.Errorf("rpc call limit exceeded (%d max per evaluation)", c.max)
	}
	return nil
}

// AddDuration adds the duration of an RPC call to the cumulative total.
// Returns an error if the cumulative duration exceeds the configured limit.
func (c *RPCCallCounter) AddDuration(d time.Duration) error {
	c.cumulativeDur += d
	if c.cumulativeDur > c.maxTotalTime {
		return fmt.Errorf("rpc cumulative time limit exceeded (%s max, used %s)", c.maxTotalTime, c.cumulativeDur)
	}
	return nil
}

// CumulativeDuration returns the total time spent in RPC calls.
func (c *RPCCallCounter) CumulativeDuration() time.Duration {
	return c.cumulativeDur
}
