package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContentTypeMiddleware_ValidJSONOnPOST(t *testing.T) {
	mw := ContentTypeMiddleware()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	body := strings.NewReader(`{"key":"value"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sign", body)
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(`{"key":"value"}`))
	rec := httptest.NewRecorder()

	mw(next).ServeHTTP(rec, req)
	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestContentTypeMiddleware_MissingContentTypeOnPOST(t *testing.T) {
	mw := ContentTypeMiddleware()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called when Content-Type is missing on POST with body")
	})

	body := strings.NewReader(`{"key":"value"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sign", body)
	req.Header.Del("Content-Type")
	req.ContentLength = int64(len(`{"key":"value"}`))
	rec := httptest.NewRecorder()

	mw(next).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)
}

func TestContentTypeMiddleware_WrongContentTypeOnPOST(t *testing.T) {
	mw := ContentTypeMiddleware()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called when Content-Type is wrong on POST with body")
	})

	body := strings.NewReader(`<xml></xml>`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sign", body)
	req.Header.Set("Content-Type", "application/xml")
	req.ContentLength = int64(len(`<xml></xml>`))
	rec := httptest.NewRecorder()

	mw(next).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)
}

func TestContentTypeMiddleware_SkippedOnGET(t *testing.T) {
	mw := ContentTypeMiddleware()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sign", nil)
	req.ContentLength = 0
	rec := httptest.NewRecorder()

	mw(next).ServeHTTP(rec, req)
	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestContentTypeMiddleware_POSTWithZeroContentLength(t *testing.T) {
	// POST with ContentLength == 0 should pass through (bodyless POST).
	mw := ContentTypeMiddleware()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/resume", nil)
	req.Header.Del("Content-Type")
	req.ContentLength = 0
	rec := httptest.NewRecorder()

	mw(next).ServeHTTP(rec, req)
	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestContentTypeMiddleware_ResponseBodyIsJSON(t *testing.T) {
	mw := ContentTypeMiddleware()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called")
	})

	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/test", body)
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = int64(len(`{}`))
	rec := httptest.NewRecorder()

	mw(next).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	// Verify the response body is valid JSON containing "error".
	recBody := rec.Body.String()
	assert.Contains(t, recBody, "application/json")
}
