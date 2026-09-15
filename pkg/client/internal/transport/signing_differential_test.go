//go:build sdkgen

// ⛔ 这个 tag 不是「可选的慢测试」,是**构建前提**:本文件 import
// pkg/client/internal/gen,而那份 SDK 是生成的、**不入库**(2026-09-15)。
// 没有 tag 的话,`make test` 的 cli 层(含 ./pkg/...)会在一台还没生成过 SDK 的
// 机器上编译失败 —— 而失败信息是 `undefined: gen.Client`,读不出「你需要先生成」。
//
// ⚠️ 实测过一个更糟的形态,写在这里免得有人把 tag 去掉:`go list` 只做**包级**
// 解析,gen/ 目录里还有手写的 doc.go,所以 import 路径解析得到 —— 门禁 ①
// (「每个测试文件都被某一层编译到」)会**绿**,而 `go test` 编译不过。
// 也就是说这一类错误没有任何门禁抓得住,只有真的跑那一层才会知道。
//
// 跑它:`make test LAYER=sdk-diff`(层定义在 scripts/lib/layers.sh,
// 前置 `make sdk WHAT=go` 写在那里)。

package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/gen"
)

// Differential test: the generated client + SigningRequestEditor must sign
// **byte-identically** to the hand-written Transport.
//
// ⛔ Why this test and not "it works against a daemon": authentication failure
// here is a 401 whose message mentions neither the path nor its encoding. The
// bug that produces it — signing r.URL.Path instead of r.URL.EscapedPath() —
// is invisible on every id without a '/' in it, which is all of them except
// templates and presets. A smoke test would pass. Proposal §4.3 asks for this
// one explicitly, and it is the reason a generated SDK is allowed to exist
// here at all: without it, "generated SDK" and "SDK that 401s" are the same
// artifact until somebody in production finds out.
//
// The comparison is genuinely byte-level, not "both verify": the hand-written
// client runs first and its timestamp and nonce are replayed into the editor,
// so the two X-Signature headers are over the same five fields and must be
// equal as strings. Anything the two clients disagree about — method, escaped
// path, query, body — changes the signature and fails.

const diffTestSeedHex = "4242424242424242424242424242424242424242424242424242424242424242"

// recorder is an http.RoundTripper that keeps the request it was handed and
// answers 200 {} so neither client errors out before we can look at it.
type recorder struct {
	method string
	// escapedPathAndQuery is what the *server* would sign: EscapedPath plus
	// "?" plus RawQuery when there is one. ⚠️ Read off the outgoing request
	// exactly the way middleware/auth.go reads it off the incoming one.
	escapedPathAndQuery string
	body                []byte
	hdr                 http.Header
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.method = req.Method
	p := req.URL.EscapedPath()
	if req.URL.RawQuery != "" {
		p += "?" + req.URL.RawQuery
	}
	r.escapedPathAndQuery = p
	r.body = nil
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		r.body = b
	}
	r.hdr = req.Header.Clone()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(`{}`))),
		Request:    req,
	}, nil
}

// verifyLikeServer rebuilds the signed message the way internal/api/middleware
// /auth.go does and checks the Ed25519 signature. ⛔ Deliberately a second
// implementation rather than a call into Auth.SignRequest: if both sides of a
// differential test call the same helper, the test proves the helper is
// consistent with itself.
func verifyLikeServer(t *testing.T, pub ed25519.PublicKey, rec *recorder) string {
	t.Helper()
	ts := rec.hdr.Get("X-Timestamp")
	nonce := rec.hdr.Get("X-Nonce")
	sig := rec.hdr.Get("X-Signature")
	if ts == "" || nonce == "" || sig == "" {
		t.Fatalf("missing auth headers: ts=%q nonce=%q sig=%q", ts, nonce, sig)
	}
	if _, err := strconv.ParseInt(ts, 10, 64); err != nil {
		t.Fatalf("X-Timestamp %q is not an integer: %v", ts, err)
	}
	sum := sha256.Sum256(rec.body)
	msg := fmt.Sprintf("%s|%s|%s|%s|%x", ts, nonce, rec.method, rec.escapedPathAndQuery, sum)
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("X-Signature is not base64: %v", err)
	}
	if !ed25519.Verify(pub, []byte(msg), raw) {
		t.Fatalf("server-side verification failed for message %q", msg)
	}
	return msg
}

func diffKey(t *testing.T) (ed25519.PrivateKey, *Auth) {
	t.Helper()
	priv, err := ParsePrivateKey(nil, diffTestSeedHex, "")
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	return priv, NewAuth(priv)
}

func TestGeneratedClientSignsIdenticallyToHandWritten(t *testing.T) {
	const baseURL = "http://signer.invalid:8548"
	const keyID = "agent"

	priv, auth := diffKey(t)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("private key did not yield an ed25519 public key")
	}

	cases := []struct {
		name string
		// handWritten drives pkg/client's existing Transport.
		handWritten func(t *testing.T, tr *Transport)
		// generated drives the oapi-codegen client for the same logical call.
		generated func(t *testing.T, c *gen.Client) error
	}{
		{
			// The ordinary shape: no path parameter, no query, no body.
			name: "GET collection",
			handWritten: func(t *testing.T, tr *Transport) {
				if err := tr.Request(context.Background(), http.MethodGet,
					"/api/v1/evm/rules", nil, nil, http.StatusOK); err != nil {
					t.Fatalf("hand-written: %v", err)
				}
			},
			generated: func(t *testing.T, c *gen.Client) error {
				_, err := c.GetApiV1EvmRules(context.Background(), nil)
				return err
			},
		},
		{
			// ⭐ The case the whole editor exists for. A template id contains
			// '/', so the wire form is %2F and req.URL.Path decodes it back.
			// Signing Path instead of EscapedPath passes every other test in
			// this file and fails only here.
			name: "GET item whose id contains a slash",
			handWritten: func(t *testing.T, tr *Transport) {
				// ⚠️ This is what pkg/client/templates does: url.PathEscape on
				// the id before it reaches Transport.
				if err := tr.Request(context.Background(), http.MethodGet,
					"/api/v1/templates/evm%2Ferc20", nil, nil, http.StatusOK); err != nil {
					t.Fatalf("hand-written: %v", err)
				}
			},
			generated: func(t *testing.T, c *gen.Client) error {
				// ⚠️ The generated client takes the *unescaped* id and encodes
				// it itself (runtime.StyleParamWithOptions). That the two
				// arrive at the same bytes is the point of the case.
				_, err := c.GetApiV1TemplatesId(context.Background(), "evm/erc20")
				return err
			},
		},
		{
			// A body: proves GetBody() was used and the hash covers what is
			// actually sent.
			name: "POST with JSON body",
			handWritten: func(t *testing.T, tr *Transport) {
				body := gen.EvmCreateRuleRequest{Name: "diff-test"}
				if err := tr.Request(context.Background(), http.MethodPost,
					"/api/v1/evm/rules", body, nil, http.StatusOK); err != nil {
					t.Fatalf("hand-written: %v", err)
				}
			},
			generated: func(t *testing.T, c *gen.Client) error {
				_, err := c.PostApiV1EvmRules(context.Background(),
					gen.PostApiV1EvmRulesJSONRequestBody{Name: "diff-test"})
				return err
			},
		},
		{
			// A query string: proves the "?" is appended only once and the
			// signed string carries it.
			name: "GET with one query parameter",
			handWritten: func(t *testing.T, tr *Transport) {
				if err := tr.Request(context.Background(), http.MethodGet,
					"/api/v1/evm/rules?enabled=true", nil, nil, http.StatusOK); err != nil {
					t.Fatalf("hand-written: %v", err)
				}
			},
			generated: func(t *testing.T, c *gen.Client) error {
				enabled := "true"
				_, err := c.GetApiV1EvmRules(context.Background(),
					&gen.GetApiV1EvmRulesParams{Enabled: &enabled})
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// ---- 1. hand-written ----
			hwRec := &recorder{}
			tr, err := NewTransport(Config{
				BaseURL:    baseURL,
				APIKeyID:   keyID,
				HTTPClient: &http.Client{Transport: hwRec},
			}, auth)
			if err != nil {
				t.Fatalf("NewTransport: %v", err)
			}
			tc.handWritten(t, tr)
			hwMsg := verifyLikeServer(t, pub, hwRec)

			// ---- 2. generated, replaying the same timestamp and nonce ----
			//
			// ⛔ Pinning them is what makes this a *byte* comparison rather
			// than "both happen to verify". Two clients that disagree about
			// the path would each verify against their own message; only
			// equal inputs make equal signatures.
			ts, err := strconv.ParseInt(hwRec.hdr.Get("X-Timestamp"), 10, 64)
			if err != nil {
				t.Fatalf("parsing recorded timestamp: %v", err)
			}
			editor := NewSigningRequestEditor(keyID, auth)
			editor.now = func() time.Time { return time.UnixMilli(ts) }
			editor.nonce = func() string { return hwRec.hdr.Get("X-Nonce") }

			genRec := &recorder{}
			c, err := gen.NewClient(baseURL,
				gen.WithHTTPClient(&http.Client{Transport: genRec}),
				gen.WithRequestEditorFn(editor.Edit))
			if err != nil {
				t.Fatalf("gen.NewClient: %v", err)
			}
			if err := tc.generated(t, c); err != nil {
				t.Fatalf("generated: %v", err)
			}
			genMsg := verifyLikeServer(t, pub, genRec)

			// ---- 3. the assertions ----
			if hwRec.method != genRec.method {
				t.Errorf("method differs: hand-written %q, generated %q", hwRec.method, genRec.method)
			}
			if hwRec.escapedPathAndQuery != genRec.escapedPathAndQuery {
				t.Errorf("signed path differs:\n  hand-written %q\n  generated    %q",
					hwRec.escapedPathAndQuery, genRec.escapedPathAndQuery)
			}
			if !bytes.Equal(hwRec.body, genRec.body) {
				t.Errorf("body differs:\n  hand-written %q\n  generated    %q", hwRec.body, genRec.body)
			}
			if hwMsg != genMsg {
				t.Errorf("signed message differs:\n  hand-written %q\n  generated    %q", hwMsg, genMsg)
			}
			hwSig := hwRec.hdr.Get("X-Signature")
			genSig := genRec.hdr.Get("X-Signature")
			if hwSig != genSig {
				t.Fatalf("X-Signature differs:\n  hand-written %s\n  generated    %s", hwSig, genSig)
			}
			for _, h := range []string{"X-API-Key-ID", "X-Timestamp", "X-Nonce"} {
				if hwRec.hdr.Get(h) != genRec.hdr.Get(h) {
					t.Errorf("%s differs: %q vs %q", h, hwRec.hdr.Get(h), genRec.hdr.Get(h))
				}
			}
			t.Logf("identical signed bytes\n  message   %s\n  signature %s", hwMsg, hwSig)
		})
	}
}

// TestSigningEditorRejectsUnreadableBody pins the one branch that must fail
// loudly rather than sign the wrong thing: a request carrying a body the
// editor cannot re-read.
//
// ⛔ Signing sha256(nil) here and sending the real body produces a 401 whose
// message is about authentication, and whose cause is three layers away.
func TestSigningEditorRejectsUnreadableBody(t *testing.T) {
	_, auth := diffKey(t)
	req, err := http.NewRequest(http.MethodPost, "http://signer.invalid/api/v1/evm/rules",
		io.NopCloser(bytes.NewReader([]byte(`{"name":"x"}`))))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// io.NopCloser is not one of the three types http.NewRequest recognises,
	// so GetBody is nil — the exact shape this guards.
	if req.GetBody != nil {
		t.Fatal("precondition: expected GetBody to be nil for an io.NopCloser body")
	}
	if err := NewSigningRequestEditor("agent", auth).Edit(context.Background(), req); err == nil {
		t.Fatal("expected an error, got nil — the editor signed a body it could not read")
	} else {
		t.Logf("refused as it should: %v", err)
	}
	if req.Header.Get("X-Signature") != "" {
		t.Error("editor set X-Signature despite failing")
	}
}

// TestSigningEditorMatchesServerPathEncoding is the narrow regression test for
// §4.3 point 1, stated as its own fact rather than as a side effect of the
// differential cases: the editor must sign the escaped path.
func TestSigningEditorMatchesServerPathEncoding(t *testing.T) {
	priv, auth := diffKey(t)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("private key did not yield an ed25519 public key")
	}
	req, err := http.NewRequest(http.MethodGet,
		"http://signer.invalid/api/v1/templates/evm%2Ferc20?q=a%20b", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if req.URL.Path == req.URL.EscapedPath() {
		t.Fatalf("precondition: Path %q and EscapedPath %q are the same, this URL cannot tell them apart",
			req.URL.Path, req.URL.EscapedPath())
	}
	if err := NewSigningRequestEditor("agent", auth).Edit(context.Background(), req); err != nil {
		t.Fatalf("Edit: %v", err)
	}
	sum := sha256.Sum256(nil)
	want := fmt.Sprintf("%s|%s|GET|/api/v1/templates/evm%%2Ferc20?q=a%%20b|%x",
		req.Header.Get("X-Timestamp"), req.Header.Get("X-Nonce"), sum)
	raw, err := base64.StdEncoding.DecodeString(req.Header.Get("X-Signature"))
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	if !ed25519.Verify(pub, []byte(want), raw) {
		t.Fatalf("signature is not over the escaped path; expected message %q", want)
	}
	t.Logf("signed over %q", want)
}
