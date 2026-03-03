package notify

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// roundTripFunc implements http.RoundTripper using a plain function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// ---------- NewPushoverClient ----------

func TestNewPushoverClient_EmptyToken(t *testing.T) {
	_, err := NewPushoverClient("", 30, 300, 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "app token is required")
}

func TestNewPushoverClient_MaxRetriesZero(t *testing.T) {
	_, err := NewPushoverClient("tok", 30, 300, 0, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max retries must be greater than 0")
}

func TestNewPushoverClient_MaxRetriesNegative(t *testing.T) {
	_, err := NewPushoverClient("tok", 30, 300, -1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max retries must be greater than 0")
}

func TestNewPushoverClient_NegativeRetryDelay(t *testing.T) {
	_, err := NewPushoverClient("tok", 30, 300, 1, -1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "retry delay must be non-negative")
}

func TestNewPushoverClient_Valid(t *testing.T) {
	c, err := NewPushoverClient("tok", 30, 300, 3, 1)
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "tok", c.appToken)
	assert.Equal(t, 30, c.retry)
	assert.Equal(t, 300, c.expire)
	assert.Equal(t, 3, c.maxRetries)
}

// ---------- maskUserKey ----------

func TestMaskUserKey_Short(t *testing.T) {
	assert.Equal(t, "***", maskUserKey(""))
	assert.Equal(t, "***", maskUserKey("abc"))
	assert.Equal(t, "***", maskUserKey("12345678")) // exactly 8 chars
}

func TestMaskUserKey_Normal(t *testing.T) {
	assert.Equal(t, "abcd***fghi", maskUserKey("abcdefghi")) // 9 chars
	assert.Equal(t, "abcd***uvwx", maskUserKey("abcdefghijklmnopqrstuvwx"))
}

// ---------- helpers for mock HTTP responses ----------

// newJSONResponse builds an *http.Response with the given status and JSON body.
func newJSONResponse(status int, v interface{}) *http.Response {
	body, _ := json.Marshal(v)
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytesReader(body)),
	}
}

// bytesReader wraps a byte slice into a reader for use in http.Response.Body.
func bytesReader(b []byte) io.Reader {
	return &byteReadCloser{data: b}
}

type byteReadCloser struct {
	data []byte
	off  int
}

func (r *byteReadCloser) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

// newPushoverClientWithRT creates a PushoverClient with zero retry delay
// and replaces its httpClient transport with the given RoundTripper.
func newPushoverClientWithRT(rt http.RoundTripper) *PushoverClient {
	c, _ := NewPushoverClient("test-token", 30, 300, 1, 0)
	c.httpClient = &http.Client{Transport: rt}
	return c
}

// ---------- SendNotification ----------

func TestSendNotification_Success(t *testing.T) {
	var received PushoverRequest
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, "POST", req.Method)
		assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
		err := json.NewDecoder(req.Body).Decode(&received)
		require.NoError(t, err)
		return newJSONResponse(200, PushoverResponse{Status: 1, Request: "req-123"}), nil
	})

	c := newPushoverClientWithRT(rt)
	err := c.SendNotification("user-key", "hello", 0, "pushover")
	require.NoError(t, err)

	assert.Equal(t, "test-token", received.Token)
	assert.Equal(t, "user-key", received.User)
	assert.Equal(t, "hello", received.Message)
	assert.Equal(t, 0, received.Priority)
	assert.Equal(t, "pushover", received.Sound)
	// Non-emergency: retry and expire should NOT be set
	assert.Equal(t, 0, received.Retry)
	assert.Equal(t, 0, received.Expire)
}

func TestSendNotification_Priority2_SetsRetryExpire(t *testing.T) {
	var received PushoverRequest
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		_ = json.NewDecoder(req.Body).Decode(&received)
		return newJSONResponse(200, PushoverResponse{Status: 1, Request: "req-em"}), nil
	})

	c := newPushoverClientWithRT(rt)
	err := c.SendNotification("user-key", "emergency!", 2, "persistent")
	require.NoError(t, err)
	assert.Equal(t, 2, received.Priority)
	assert.Equal(t, 30, received.Retry)
	assert.Equal(t, 300, received.Expire)
}

func TestSendNotification_APIError(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newJSONResponse(200, PushoverResponse{
			Status: 0,
			Errors: []string{"user key is invalid"},
		}), nil
	})

	c := newPushoverClientWithRT(rt)
	err := c.SendNotification("bad-key", "msg", 0, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user key is invalid")
}

func TestSendNotification_APIError_NoErrorSlice(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newJSONResponse(200, PushoverResponse{Status: 0}), nil
	})

	c := newPushoverClientWithRT(rt)
	err := c.SendNotification("bad-key", "msg", 0, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown error")
}

func TestSendNotification_HTTPFailure_RetriesExhausted(t *testing.T) {
	calls := 0
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return nil, fmt.Errorf("connection refused")
	})

	// 2 retries with 0 delay so the test is fast
	c, _ := NewPushoverClient("tok", 30, 300, 2, 0)
	c.httpClient = &http.Client{Transport: rt}

	err := c.SendNotification("u", "m", 0, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed after 2 attempts")
	assert.Contains(t, err.Error(), "connection refused")
	assert.Equal(t, 2, calls)
}

func TestSendNotification_DecodeFailure(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(&byteReadCloser{data: []byte("not json")}),
		}, nil
	})

	c := newPushoverClientWithRT(rt)
	err := c.SendNotification("u", "m", 0, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode response")
}

func TestSendNotification_RetriesUntilSuccess(t *testing.T) {
	calls := 0
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls < 3 {
			return nil, fmt.Errorf("temporary error")
		}
		return newJSONResponse(200, PushoverResponse{Status: 1, Request: "ok"}), nil
	})

	c, _ := NewPushoverClient("tok", 30, 300, 3, 0)
	c.httpClient = &http.Client{Transport: rt}

	err := c.SendNotification("u", "m", 0, "")
	require.NoError(t, err)
	assert.Equal(t, 3, calls)
}

// ---------- SendEmergencyNotification ----------

func TestSendEmergencyNotification(t *testing.T) {
	var received PushoverRequest
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		_ = json.NewDecoder(req.Body).Decode(&received)
		return newJSONResponse(200, PushoverResponse{Status: 1, Request: "em"}), nil
	})

	c := newPushoverClientWithRT(rt)
	err := c.SendEmergencyNotification("user", "alert!")
	require.NoError(t, err)
	assert.Equal(t, 2, received.Priority)
	assert.Equal(t, "persistent", received.Sound)
	assert.Equal(t, 30, received.Retry)
	assert.Equal(t, 300, received.Expire)
}

// ---------- SendToUsers ----------

func TestSendToUsers_EmptyKeys(t *testing.T) {
	c := newPushoverClientWithRT(nil)
	err := c.SendToUsers(nil, "msg", 0, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user keys are required")
}

func TestSendToUsers_EmptyMessage(t *testing.T) {
	c := newPushoverClientWithRT(nil)
	err := c.SendToUsers([]string{"u1"}, "", 0, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "message is required")
}

func TestSendToUsers_AllSucceed(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newJSONResponse(200, PushoverResponse{Status: 1, Request: "ok"}), nil
	})

	c := newPushoverClientWithRT(rt)
	err := c.SendToUsers([]string{"u1", "u2", "u3"}, "msg", 0, "pushover")
	require.NoError(t, err)
}

func TestSendToUsers_AllFail(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("network error")
	})

	c := newPushoverClientWithRT(rt)
	err := c.SendToUsers([]string{"u1", "u2"}, "msg", 0, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to send to any user")
}

func TestSendToUsers_PartialFailure(t *testing.T) {
	call := 0
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		call++
		if call == 1 {
			return nil, fmt.Errorf("network error")
		}
		return newJSONResponse(200, PushoverResponse{Status: 1, Request: "ok"}), nil
	})

	c := newPushoverClientWithRT(rt)
	err := c.SendToUsers([]string{"fail-user", "ok-user"}, "msg", 0, "")
	require.NoError(t, err) // partial success is OK
}
