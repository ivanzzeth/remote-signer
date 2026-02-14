package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebhookClient_SendToURLs_Success(t *testing.T) {
	var received WebhookPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		err := json.NewDecoder(r.Body).Decode(&received)
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, err := NewWebhookClient(5*time.Second, nil)
	require.NoError(t, err)

	err = client.SendToURLs([]string{srv.URL}, "hello webhook")
	require.NoError(t, err)
	assert.Equal(t, "hello webhook", received.Text)
	assert.NotEmpty(t, received.Timestamp)
}

func TestWebhookClient_SendToURLs_CustomHeaders(t *testing.T) {
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, err := NewWebhookClient(5*time.Second, map[string]string{
		"Authorization": "Bearer test-token",
	})
	require.NoError(t, err)

	err = client.SendToURLs([]string{srv.URL}, "with auth")
	require.NoError(t, err)
	assert.Equal(t, "Bearer test-token", authHeader)
}

func TestWebhookClient_SendToURLs_PartialFailure(t *testing.T) {
	var successCalls atomic.Int32

	goodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		successCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer goodSrv.Close()

	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer badSrv.Close()

	client, err := NewWebhookClient(5*time.Second, nil)
	require.NoError(t, err)

	// One good, one bad — should succeed overall
	err = client.SendToURLs([]string{badSrv.URL, goodSrv.URL}, "partial")
	require.NoError(t, err)
	assert.Equal(t, int32(1), successCalls.Load())
}

func TestWebhookClient_SendToURLs_AllFail(t *testing.T) {
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer badSrv.Close()

	client, err := NewWebhookClient(5*time.Second, nil)
	require.NoError(t, err)

	err = client.SendToURLs([]string{badSrv.URL}, "fail")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to send to any webhook")
}

func TestWebhookClient_SendToURLs_EmptyInputs(t *testing.T) {
	client, err := NewWebhookClient(5*time.Second, nil)
	require.NoError(t, err)

	err = client.SendToURLs(nil, "msg")
	assert.Error(t, err)

	err = client.SendToURLs([]string{"http://localhost"}, "")
	assert.Error(t, err)
}

func TestWebhookClient_DefaultTimeout(t *testing.T) {
	client, err := NewWebhookClient(0, nil)
	require.NoError(t, err)
	assert.Equal(t, 10*time.Second, client.httpClient.Timeout)
}
