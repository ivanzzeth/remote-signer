package transport

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SigningRequestEditor puts this service's Ed25519 auth headers on a request
// that somebody else built — specifically, on one built by the generated
// client in pkg/client/internal/gen.
//
// # ⛔ Why this is hand-written and always will be
//
// The server signs, in middleware/auth.go:
//
//	{unix-millis}|{nonce}|{METHOD}|{EscapedPath}[?{RawQuery}]|{hex sha256(body)}
//
// OpenAPI has no way to say that. `securitySchemes` can say "there is an
// apiKey header called X-API-Key-ID"; it cannot say "and three more headers,
// one of which is a signature over those five fields joined by pipes, with the
// path in its percent-encoded form". S9 measured this: it is the one part of
// the contract the spec does not carry, which is exactly why it has to be
// written once, by hand, and tested against the client that already works.
//
// ⚠️ A generated SDK that 401s on every call is worse than no generated SDK:
// the failure surfaces as an authentication error that says nothing about
// paths or encodings, and the natural next move — "regenerate it" — cannot
// help. signing_differential_test.go exists to make that impossible to ship.
//
// # ⛔ The three things that are easy to get wrong here
//
// All three are from the proposal §4.3, and all three are asserted in the
// differential test rather than merely written down:
//
//  1. **EscapedPath(), not Path.** Template and preset ids contain '/'
//     ("evm/erc20"). The generated client percent-encodes them into the URL,
//     so req.URL.Path decodes back to "/api/v1/templates/evm/erc20" while the
//     wire — and the server — see "/api/v1/templates/evm%2Ferc20". Signing
//     Path would disagree with the server on every id that has a slash, and
//     only on those.
//  2. **Query only when RawQuery is non-empty.** A trailing "?" is a different
//     string, and the server never produces one.
//  3. **GetBody(), not Body.** Reading req.Body consumes it; the request would
//     then go out with an empty body while the signature covers the real one.
//     http.NewRequest sets GetBody for the *bytes.Reader the generated client
//     uses, so this is available — and when it is not, this refuses rather
//     than signing a hash of nothing.
type SigningRequestEditor struct {
	apiKeyID string
	auth     *Auth

	// now and nonce are swappable so the differential test can replay the
	// hand-written client's exact timestamp and nonce and compare signature
	// bytes. ⛔ Unexported on purpose: pinning a nonce in production is a
	// replay vulnerability, not a configuration option.
	now   func() time.Time
	nonce func() string
}

// NewSigningRequestEditor returns an editor that signs with the given key id
// and Ed25519 key.
func NewSigningRequestEditor(apiKeyID string, auth *Auth) *SigningRequestEditor {
	return &SigningRequestEditor{
		apiKeyID: apiKeyID,
		auth:     auth,
		now:      time.Now,
		nonce:    GenerateNonce,
	}
}

// Edit signs req in place. Its signature is deliberately identical to the
// generated client's RequestEditorFn, so it can be handed to
// gen.WithRequestEditorFn(editor.Edit) without either package importing the
// other.
func (e *SigningRequestEditor) Edit(_ context.Context, req *http.Request) error {
	if e == nil || e.auth == nil {
		return fmt.Errorf("signing request editor: no key configured")
	}

	body, err := requestBodyBytes(req)
	if err != nil {
		return err
	}

	// ⛔ EscapedPath(), and the query appended only when there is one.
	// This has to agree byte-for-byte with middleware/auth.go.
	path := req.URL.EscapedPath()
	if req.URL.RawQuery != "" {
		path = path + "?" + req.URL.RawQuery
	}

	timestamp := e.now().UnixMilli()
	nonce := e.nonce()
	signature := e.auth.SignRequest(timestamp, nonce, req.Method, path, body)

	req.Header.Set("X-API-Key-ID", e.apiKeyID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", signature)
	return nil
}

// requestBodyBytes returns the request body without consuming it.
//
// ⚠️ A nil body and an empty body are the same thing to the signature: the
// hand-written transport hashes a nil slice for bodyless requests, and
// sha256(nil) == sha256([]byte{}). ⛔ Do not "fix" this into a distinction —
// the server hashes whatever io.ReadAll gave it, which is an empty slice.
func requestBodyBytes(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	if req.GetBody == nil {
		// ⛔ Refuse rather than read. Reading req.Body here would sign the
		// right bytes and then send none of them, and the server would answer
		// 401 for a body-hash mismatch it cannot explain.
		return nil, fmt.Errorf(
			"signing request editor: request has a body but no GetBody; cannot read it without consuming it")
	}
	rc, err := req.GetBody()
	if err != nil {
		return nil, fmt.Errorf("signing request editor: GetBody: %w", err)
	}
	defer func() { _ = rc.Close() }()
	body, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("signing request editor: reading body: %w", err)
	}
	if len(body) == 0 {
		return nil, nil
	}
	return body, nil
}
