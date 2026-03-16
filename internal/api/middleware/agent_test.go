package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/stretchr/testify/assert"
)

func TestAgentOrAdminMiddleware_NoAPIKeyInContext(t *testing.T) {
	logger := newTestLogger()
	mw := AgentOrAdminMiddleware(logger)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called when there is no API key")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules", nil)
	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestAgentOrAdminMiddleware_DevKey_Denied(t *testing.T) {
	logger := newTestLogger()
	mw := AgentOrAdminMiddleware(logger)

	apiKey := &types.APIKey{
		ID:    "key-dev",
		Name:  "dev-key",
		Admin: false,
		Agent: false,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called for dev key")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules", nil)
	ctx := context.WithValue(req.Context(), APIKeyContextKey, apiKey)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestAgentOrAdminMiddleware_AdminKey_FullAccess(t *testing.T) {
	logger := newTestLogger()
	mw := AgentOrAdminMiddleware(logger)

	apiKey := &types.APIKey{
		ID:    "key-admin",
		Name:  "admin-key",
		Admin: true,
	}

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(method, "/api/v1/evm/rules", nil)
			ctx := context.WithValue(req.Context(), APIKeyContextKey, apiKey)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			mw(next).ServeHTTP(rr, req)

			assert.True(t, called, "next handler should be called for admin key with %s", method)
			assert.Equal(t, http.StatusOK, rr.Code)
		})
	}
}

func TestAgentOrAdminMiddleware_AgentKey_GETAllowed(t *testing.T) {
	logger := newTestLogger()
	mw := AgentOrAdminMiddleware(logger)

	apiKey := &types.APIKey{
		ID:    "key-agent",
		Name:  "agent-key",
		Agent: true,
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules", nil)
	ctx := context.WithValue(req.Context(), APIKeyContextKey, apiKey)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.True(t, called, "next handler should be called for agent key with GET")
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestAgentOrAdminMiddleware_AgentKey_NonGETDenied(t *testing.T) {
	logger := newTestLogger()
	mw := AgentOrAdminMiddleware(logger)

	apiKey := &types.APIKey{
		ID:    "key-agent",
		Name:  "agent-key",
		Agent: true,
	}

	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodDelete, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fatalf("next handler should not be called for agent key with %s", method)
			})

			req := httptest.NewRequest(method, "/api/v1/evm/rules", nil)
			ctx := context.WithValue(req.Context(), APIKeyContextKey, apiKey)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			mw(next).ServeHTTP(rr, req)

			assert.Equal(t, http.StatusForbidden, rr.Code)
			assert.Contains(t, rr.Body.String(), "read-only")
		})
	}
}
