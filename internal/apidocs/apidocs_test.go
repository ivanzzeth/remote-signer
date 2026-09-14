package apidocs

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestSpecIsAUsableOpenAPIDocument checks the three things a consumer of the
// embedded bytes assumes before it parses anything else.
//
// ⚠️ This is deliberately NOT a second copy of gate ⑭ (scripts/check-openapi.sh).
// The gate compares the document against the route table and regenerates it to
// prove it is not stale; both need swag and cmd/archcheck, and neither belongs in
// a unit test. What a test adds is the thing the gate cannot see: that the bytes
// which actually got compiled into this binary are a document at all. A truncated
// or hand-edited openapi.json passes `go build` and fails here.
func TestSpecIsAUsableOpenAPIDocument(t *testing.T) {
	if len(Spec) == 0 {
		t.Fatal("embedded spec is empty — run `make openapi`")
	}

	var doc struct {
		OpenAPI string                    `json:"openapi"`
		Info    map[string]any            `json:"info"`
		Paths   map[string]map[string]any `json:"paths"`
		Comps   map[string]map[string]any `json:"components"`
	}
	if err := json.Unmarshal(Spec, &doc); err != nil {
		t.Fatalf("embedded spec is not valid JSON: %v", err)
	}

	// ⛔ 3.1 specifically: swag emits Swagger 2.0 without --v3.1, and the two are
	// different formats, not different versions of one. A generator downstream
	// (oapi-codegen, openapi-typescript) reads this field to decide how to parse.
	if !strings.HasPrefix(doc.OpenAPI, "3.1") {
		t.Errorf("openapi = %q, want 3.1.x — the generation command lost --v3.1", doc.OpenAPI)
	}
	if len(doc.Paths) == 0 {
		t.Error("the document has no paths — a spec generated from zero parsed files looks exactly like this")
	}
	if doc.Info["title"] == "" || doc.Info["title"] == nil {
		t.Error("info.title is empty — the general API info block in doc.go was not picked up")
	}
}

// TestEverySpecPathIsAbsolute pins the one shape mistake an annotation can make
// that nothing else would notice: `@Router api/v1/x [get]` (no leading slash)
// generates a path a client cannot join to a base URL.
func TestEverySpecPathIsAbsolute(t *testing.T) {
	var doc struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(Spec, &doc); err != nil {
		t.Fatalf("embedded spec is not valid JSON: %v", err)
	}
	for p := range doc.Paths {
		if !strings.HasPrefix(p, "/") {
			t.Errorf("path %q does not start with '/' — check the @Router line that produced it", p)
		}
	}
}
