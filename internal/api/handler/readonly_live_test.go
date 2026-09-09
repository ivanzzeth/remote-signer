package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestReadOnly_IsReadLiveNotFrozen pins the behaviour this repository promises
// in internal/settings/model.go — settings written through the admin API become
// "effective without a daemon restart" — for the *_api_readonly switches.
//
// Until 2026-09-10 that promise was false for them. The value was copied out of
// the settings snapshot into RouterConfig at boot and captured again by each
// handler's constructor, so flipping rules_api_readonly in the Web UI changed
// the database, changed the snapshot, and changed no behaviour at all. Nothing
// failed; the switch simply did not do anything until the next restart.
//
// The check is the flip: one handler, one source, two answers.
func TestReadOnly_IsReadLiveNotFrozen(t *testing.T) {
	readOnly := false
	h := &APIKeyHandler{readOnly: func() bool { return readOnly }}

	if h.isReadOnly() {
		t.Fatal("expected writable while the source says false")
	}
	readOnly = true // what the settings reloader does to the snapshot
	if !h.isReadOnly() {
		t.Fatal("handler kept the old value — the switch is frozen again")
	}
	readOnly = false
	if h.isReadOnly() {
		t.Fatal("handler did not follow the source back")
	}
}

// A nil source is how the router spells "no settings manager" (tests, and any
// embedder that builds a Router without one). It must read as permissive rather
// than panic: a response package that panics on a missing optional dependency
// is worse than one that stays quiet.
func TestReadOnly_NilSourceIsPermissive(t *testing.T) {
	h := &APIKeyHandler{}
	if h.isReadOnly() {
		t.Fatal("nil source should read as not read-only")
	}
}

// And the switch has to actually gate a request, not just answer a method.
func TestReadOnly_BlocksWriteWhenLiveSourceFlips(t *testing.T) {
	readOnly := false
	h := &APIKeyHandler{readOnly: func() bool { return readOnly }}

	readOnly = true
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/api-keys/some-id", nil)
	h.deleteAPIKey(w, req, "some-id")

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 once the live source says read-only", w.Code)
	}
}
