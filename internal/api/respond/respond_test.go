package respond

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestJSON_WritesBodyAndStatus(t *testing.T) {
	w := httptest.NewRecorder()
	JSON(w, map[string]int{"n": 1}, http.StatusCreated, nil)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusCreated)
	}
	if got := w.Header().Get("Content-Type"); got != contentTypeJSON {
		t.Fatalf("content-type = %q, want %q", got, contentTypeJSON)
	}
	var decoded map[string]int
	if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if decoded["n"] != 1 {
		t.Fatalf("body = %v, want n=1", decoded)
	}
}

// The {"error": ...} shape is what clients parse — all 48 of the handler copies
// this package replaced used it, so it is contract, not formatting.
func TestError_UsesTheErrorEnvelope(t *testing.T) {
	w := httptest.NewRecorder()
	Error(w, "nope", http.StatusBadRequest, nil)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	var decoded map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if decoded["error"] != "nope" {
		t.Fatalf("body = %v, want error=nope", decoded)
	}
}

// An encode failure cannot change the status — it is already on the wire — so
// the log line is the only signal that the client got truncated JSON under a
// 200. 19 of the copies logged it and 14 dropped it; this asserts the settled
// behaviour, which none of the per-handler tests did.
func TestJSON_EncodeFailureIsLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	w := httptest.NewRecorder()

	JSON(w, make(chan int), http.StatusOK, logger) // channels cannot be marshalled

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (header is written before the body)", w.Code)
	}
	if !strings.Contains(buf.String(), "failed to encode response") {
		t.Fatalf("encode failure was not logged; log was %q", buf.String())
	}
}

// A nil logger is the old `_ =` behaviour: drop the error rather than panic.
// Some handlers predate having a logger, and a response package that panics on
// one is worse than one that stays quiet.
func TestJSON_NilLoggerDoesNotPanic(t *testing.T) {
	w := httptest.NewRecorder()
	JSON(w, make(chan int), http.StatusOK, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}
