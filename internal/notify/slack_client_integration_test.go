//go:build integration

package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------- ReplyToChannel ----------

func TestReplyToChannel_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		assert.Equal(t, "hello", body["text"])
		assert.Equal(t, "in_channel", body["response_type"])
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, _ := NewSlackClient("xoxb-tok")
	err := c.ReplyToChannel(srv.URL, "hello", "in_channel")
	require.NoError(t, err)
}

func TestReplyToChannel_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c, _ := NewSlackClient("xoxb-tok")
	err := c.ReplyToChannel(srv.URL, "msg", "ephemeral")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 502")
}

func TestReplyToChannel_HTTPFailure(t *testing.T) {
	c, _ := NewSlackClient("xoxb-tok")
	// Use an unreachable URL
	err := c.ReplyToChannel("http://127.0.0.1:1/bad", "msg", "in_channel")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to post response")
}
