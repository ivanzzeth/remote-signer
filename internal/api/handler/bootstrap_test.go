package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/bootstrap"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// fakeAPIKeyRepo is a minimal in-memory APIKeyRepository for testing the
// bootstrap handler. hasAdmin gates Get("admin") — the only behaviour the
// handler actually cares about. Concurrent flips are racey but that's
// fine for these tests.
type fakeAPIKeyRepo struct {
	hasAdmin int64 // atomic: 0 = no admin, !=0 = admin row present
}

func (f *fakeAPIKeyRepo) Count(_ context.Context, _ storage.APIKeyFilter) (int, error) {
	if atomic.LoadInt64(&f.hasAdmin) != 0 {
		return 1, nil
	}
	return 0, nil
}

func (f *fakeAPIKeyRepo) Get(_ context.Context, id string) (*types.APIKey, error) {
	if id == "admin" && atomic.LoadInt64(&f.hasAdmin) != 0 {
		return &types.APIKey{ID: "admin", Role: types.RoleAdmin}, nil
	}
	return nil, types.ErrNotFound
}

// Other methods are no-ops — the bootstrap handler only ever queries
// the admin row + delegates the actual create work to the AdminCreator
// closure.
func (f *fakeAPIKeyRepo) Create(context.Context, *types.APIKey) error { return nil }
func (f *fakeAPIKeyRepo) Update(context.Context, *types.APIKey) error { return nil }
func (f *fakeAPIKeyRepo) Delete(context.Context, string) error        { return nil }
func (f *fakeAPIKeyRepo) List(context.Context, storage.APIKeyFilter) ([]*types.APIKey, error) {
	return nil, nil
}
func (f *fakeAPIKeyRepo) UpdateLastUsed(context.Context, string) error { return nil }
func (f *fakeAPIKeyRepo) DeleteBySourceExcluding(context.Context, string, []string) (int64, error) {
	return 0, nil
}
func (f *fakeAPIKeyRepo) BackfillSource(context.Context, string) (int64, error) { return 0, nil }

// errRepo always errors on Get. Used to verify the handler reports 500
// without leaking the underlying message to the unauth caller.
type errRepo struct{}

func (errRepo) Count(context.Context, storage.APIKeyFilter) (int, error) {
	return 0, errors.New("synthetic db error")
}
func (errRepo) Get(context.Context, string) (*types.APIKey, error) {
	return nil, errors.New("synthetic db error")
}
func (errRepo) Create(context.Context, *types.APIKey) error                         { return nil }
func (errRepo) Update(context.Context, *types.APIKey) error                         { return nil }
func (errRepo) Delete(context.Context, string) error                                { return nil }
func (errRepo) List(context.Context, storage.APIKeyFilter) ([]*types.APIKey, error) { return nil, nil }
func (errRepo) UpdateLastUsed(context.Context, string) error                        { return nil }
func (errRepo) DeleteBySourceExcluding(context.Context, string, []string) (int64, error) {
	return 0, nil
}
func (errRepo) BackfillSource(context.Context, string) (int64, error) { return 0, nil }

// silentLogger gets shoved into the handler under test so test output
// isn't polluted with the success-path log line.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestBootstrap_Status_EmptyRepoReportsNeedsBootstrap(t *testing.T) {
	// Why this matters: the SPA reads this endpoint before showing the
	// login page. If we ever flip the polarity (e.g. forgot to negate
	// count==0), the UI would deadlock — bootstrap form never appears
	// on a fresh install.
	h := NewBootstrapHandler(&fakeAPIKeyRepo{hasAdmin: 0}, dummyCreator, silentLogger())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/status", nil)
	rec := httptest.NewRecorder()
	h.ServeStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", rec.Code)
	}
	var got statusResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.NeedsBootstrap {
		t.Errorf("needs_bootstrap = false, want true on empty repo")
	}
}

func TestBootstrap_Status_NonEmptyRepoReportsConfigured(t *testing.T) {
	// Symmetric guard for the polarity check above — once any key
	// exists, the SPA must route past the bootstrap form to login.
	h := NewBootstrapHandler(&fakeAPIKeyRepo{hasAdmin: 1}, dummyCreator, silentLogger())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/status", nil)
	rec := httptest.NewRecorder()
	h.ServeStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", rec.Code)
	}
	var got statusResponse
	_ = json.NewDecoder(rec.Body).Decode(&got)
	if got.NeedsBootstrap {
		t.Errorf("needs_bootstrap = true on non-empty repo")
	}
}

func TestBootstrap_Status_RejectsNonGET(t *testing.T) {
	// The endpoint is supposed to be read-only and idempotent. A
	// stray POST should bounce — otherwise we lose the guarantee that
	// the unauth surface is harmless to probe.
	h := NewBootstrapHandler(&fakeAPIKeyRepo{}, dummyCreator, silentLogger())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/status", nil)
	rec := httptest.NewRecorder()
	h.ServeStatus(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status code = %d, want 405", rec.Code)
	}
}

func TestBootstrap_Status_500OnRepoError(t *testing.T) {
	// If the database flaps mid-startup, the status check should fail
	// cleanly with a generic 500 — not leak "synthetic db error" or
	// similar to an unauth caller.
	h := NewBootstrapHandler(errRepo{}, dummyCreator, silentLogger())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/status", nil)
	rec := httptest.NewRecorder()
	h.ServeStatus(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status code = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "synthetic") {
		t.Errorf("response leaks internal error message: %s", rec.Body.String())
	}
}

func TestBootstrap_Admin_HappyPath(t *testing.T) {
	// End-to-end on the success path: a valid password produces a 200,
	// returns the keystore paths the closure reported, and the handler
	// flags status="ok". This is the path the web UI's setup form
	// hits on first install.
	calledWith := []byte(nil)
	creator := func(_ context.Context, password []byte) (*bootstrap.AdminResult, error) {
		// Copy so the handler's defer-zeroise doesn't wipe the test
		// observation before we can assert on it.
		calledWith = append([]byte{}, password...)
		return &bootstrap.AdminResult{
			KeystorePath: "/home/test/.remote-signer/apikeys/admin.keystore.json",
			PubKeyPath:   "/home/test/.remote-signer/apikeys/admin.key.pub",
			PubKeyHex:    "deadbeef" + strings.Repeat("0", 56),
		}, nil
	}
	h := NewBootstrapHandler(&fakeAPIKeyRepo{}, creator, silentLogger())

	body, _ := json.Marshal(map[string]string{"password": "swordfish-2026"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/admin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeAdmin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["status"] != "ok" {
		t.Errorf("status = %q, want ok", got["status"])
	}
	if got["keystore_path"] == "" || got["public_key_hex"] == "" {
		t.Errorf("missing fields in response: %v", got)
	}
	if string(calledWith) != "swordfish-2026" {
		t.Errorf("creator got password %q, want %q", string(calledWith), "swordfish-2026")
	}
}

func TestBootstrap_Admin_AlreadyExistsReturns410(t *testing.T) {
	// The 410 distinction tells the client to drop the bootstrap flow
	// instead of retrying. A wrong status code here (e.g. 500) would
	// turn an "already done, please login" situation into a perpetual
	// retry loop in the UI.
	creator := func(context.Context, []byte) (*bootstrap.AdminResult, error) {
		return nil, bootstrap.ErrAdminAlreadyExists
	}
	h := NewBootstrapHandler(&fakeAPIKeyRepo{}, creator, silentLogger())

	body, _ := json.Marshal(map[string]string{"password": "any"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/admin", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeAdmin(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("status code = %d, want 410", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "admin_already_exists") {
		t.Errorf("response missing machine-readable code: %s", rec.Body.String())
	}
}

func TestBootstrap_Admin_RejectsMissingPassword(t *testing.T) {
	// Empty password must not reach the keystore creation path —
	// keystore.CreateEnhancedKey would otherwise produce a "key" that
	// decrypts to the same bytes for any caller.
	called := false
	creator := func(context.Context, []byte) (*bootstrap.AdminResult, error) {
		called = true
		return nil, nil
	}
	h := NewBootstrapHandler(&fakeAPIKeyRepo{}, creator, silentLogger())

	body, _ := json.Marshal(map[string]string{"password": ""})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/admin", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeAdmin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want 400", rec.Code)
	}
	if called {
		t.Error("creator was called despite empty password")
	}
}

func TestBootstrap_Admin_RejectsInvalidJSON(t *testing.T) {
	h := NewBootstrapHandler(&fakeAPIKeyRepo{}, dummyCreator, silentLogger())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/admin", strings.NewReader("not-json"))
	rec := httptest.NewRecorder()
	h.ServeAdmin(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status code = %d, want 400", rec.Code)
	}
}

func TestBootstrap_Admin_RejectsNonPOST(t *testing.T) {
	// Only POST mutates state. GET / PUT / PATCH / DELETE all bounce
	// so a misconfigured client doesn't accidentally trigger create.
	h := NewBootstrapHandler(&fakeAPIKeyRepo{}, dummyCreator, silentLogger())
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/v1/bootstrap/admin", nil)
			rec := httptest.NewRecorder()
			h.ServeAdmin(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("status code = %d, want 405", rec.Code)
			}
		})
	}
}

func TestBootstrap_Admin_CreatorErrorReturns500(t *testing.T) {
	// A generic creator failure (disk full, permission, etc.) should
	// be a 500 with a generic body — the detail goes to the daemon's
	// log, not to the unauth caller.
	creator := func(context.Context, []byte) (*bootstrap.AdminResult, error) {
		return nil, errors.New("disk full or whatever")
	}
	h := NewBootstrapHandler(&fakeAPIKeyRepo{}, creator, silentLogger())
	body, _ := json.Marshal(map[string]string{"password": "swordfish"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/admin", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeAdmin(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status code = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "disk full") {
		t.Errorf("response leaks internal error: %s", rec.Body.String())
	}
}

// dummyCreator is the placeholder used when a test exercises a code path
// before the closure ever runs (auth gate, method gate, etc.). Returning
// an obviously-wrong value would surface mis-routed tests immediately.
func dummyCreator(context.Context, []byte) (*bootstrap.AdminResult, error) {
	return nil, errors.New("dummy creator should not be reached")
}
