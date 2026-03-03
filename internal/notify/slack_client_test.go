package notify

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// slackRoundTripFunc is identical to roundTripFunc but defined here to avoid
// redeclaration issues when running both test files in the same package.
// (roundTripFunc is already defined in pushover_client_test.go.)

// slackClient creates a SlackClient whose httpClient uses the supplied
// RoundTripper so that no real HTTP calls are made.
func slackClientWithRT(rt http.RoundTripper) *SlackClient {
	c, _ := NewSlackClient("xoxb-test-token")
	c.httpClient = &http.Client{Transport: rt}
	return c
}

// ---------- NewSlackClient ----------

func TestNewSlackClient_EmptyToken(t *testing.T) {
	_, err := NewSlackClient("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bot token is required")
}

func TestNewSlackClient_Valid(t *testing.T) {
	c, err := NewSlackClient("xoxb-tok")
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "xoxb-tok", c.botToken)
}

// ---------- PostMessage ----------

func TestPostMessage_Success(t *testing.T) {
	var received map[string]interface{}
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, "POST", req.Method)
		assert.Contains(t, req.URL.String(), "chat.postMessage")
		assert.Equal(t, "Bearer xoxb-test-token", req.Header.Get("Authorization"))
		_ = json.NewDecoder(req.Body).Decode(&received)
		return newJSONResponse(200, map[string]interface{}{"ok": true}), nil
	})

	c := slackClientWithRT(rt)
	err := c.PostMessage("C123", "hello slack")
	require.NoError(t, err)
	assert.Equal(t, "C123", received["channel"])
	assert.Equal(t, "hello slack", received["text"])
}

func TestPostMessage_APIError(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newJSONResponse(200, map[string]interface{}{
			"ok":    false,
			"error": "channel_not_found",
		}), nil
	})

	c := slackClientWithRT(rt)
	err := c.PostMessage("C-bad", "msg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "channel_not_found")
}

func TestPostMessage_HTTPFailure(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connection reset")
	})

	c := slackClientWithRT(rt)
	err := c.PostMessage("C123", "msg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to post message")
}

func TestPostMessage_DecodeFailure(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(&byteReadCloser{data: []byte("bad json")}),
		}, nil
	})

	c := slackClientWithRT(rt)
	err := c.PostMessage("C123", "msg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode response")
}

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

// ---------- GetChannelMembers ----------

func TestGetChannelMembers_Success(t *testing.T) {
	callIdx := 0
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		callIdx++
		if callIdx == 1 {
			// conversations.members call
			assert.Contains(t, req.URL.String(), "conversations.members")
			assert.Contains(t, req.URL.String(), "channel=C123")
			return newJSONResponse(200, map[string]interface{}{
				"ok":      true,
				"members": []string{"U1", "U2", "U3"},
			}), nil
		}
		// users.list call (filterBots)
		return newJSONResponse(200, map[string]interface{}{
			"ok": true,
			"members": []map[string]interface{}{
				{"id": "U1", "is_bot": false, "deleted": false},
				{"id": "U2", "is_bot": true, "deleted": false},
				{"id": "U3", "is_bot": false, "deleted": false},
			},
		}), nil
	})

	c := slackClientWithRT(rt)
	members, err := c.GetChannelMembers("C123")
	require.NoError(t, err)
	// U2 is a bot, should be filtered out
	assert.Equal(t, []string{"U1", "U3"}, members)
}

func TestGetChannelMembers_APIError(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newJSONResponse(200, map[string]interface{}{
			"ok":    false,
			"error": "channel_not_found",
		}), nil
	})

	c := slackClientWithRT(rt)
	_, err := c.GetChannelMembers("C-bad")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "channel_not_found")
}

func TestGetChannelMembers_HTTPFailure(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("timeout")
	})

	c := slackClientWithRT(rt)
	_, err := c.GetChannelMembers("C123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get channel members")
}

func TestGetChannelMembers_FilterBotsFails_ReturnsAllMembers(t *testing.T) {
	callIdx := 0
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		callIdx++
		if callIdx == 1 {
			// conversations.members: success
			return newJSONResponse(200, map[string]interface{}{
				"ok":      true,
				"members": []string{"U1", "U2"},
			}), nil
		}
		// users.list: failure
		return nil, fmt.Errorf("users.list network error")
	})

	c := slackClientWithRT(rt)
	members, err := c.GetChannelMembers("C123")
	require.NoError(t, err) // filterBots failure is non-fatal
	assert.Equal(t, []string{"U1", "U2"}, members)
}

// ---------- GetUserInfo ----------

func TestGetUserInfo_Success(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		assert.Contains(t, req.URL.String(), "users.info")
		assert.Contains(t, req.URL.String(), "user=U42")
		return newJSONResponse(200, map[string]interface{}{
			"ok": true,
			"user": map[string]interface{}{
				"id":        "U42",
				"name":      "alice",
				"real_name": "Alice Smith",
			},
		}), nil
	})

	c := slackClientWithRT(rt)
	info, err := c.GetUserInfo("U42")
	require.NoError(t, err)
	assert.Equal(t, "U42", info.ID)
	assert.Equal(t, "alice", info.Name)
	assert.Equal(t, "Alice Smith", info.RealName)
}

func TestGetUserInfo_APIError(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newJSONResponse(200, map[string]interface{}{
			"ok":    false,
			"error": "user_not_found",
		}), nil
	})

	c := slackClientWithRT(rt)
	_, err := c.GetUserInfo("U-bad")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user_not_found")
}

func TestGetUserInfo_HTTPFailure(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("dns error")
	})

	c := slackClientWithRT(rt)
	_, err := c.GetUserInfo("U1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get user info")
}

// ---------- FindUserByName ----------

func TestFindUserByName_Found(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		assert.Contains(t, req.URL.String(), "users.list")
		return newJSONResponse(200, map[string]interface{}{
			"ok": true,
			"members": []map[string]interface{}{
				{"id": "U1", "name": "alice", "real_name": "Alice", "deleted": false},
				{"id": "U2", "name": "bob", "real_name": "Bob", "deleted": false},
			},
		}), nil
	})

	c := slackClientWithRT(rt)
	id, err := c.FindUserByName("bob")
	require.NoError(t, err)
	assert.Equal(t, "U2", id)
}

func TestFindUserByName_CaseInsensitive(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newJSONResponse(200, map[string]interface{}{
			"ok": true,
			"members": []map[string]interface{}{
				{"id": "U1", "name": "Alice", "real_name": "Alice", "deleted": false},
			},
		}), nil
	})

	c := slackClientWithRT(rt)
	id, err := c.FindUserByName("aLiCe")
	require.NoError(t, err)
	assert.Equal(t, "U1", id)
}

func TestFindUserByName_SkipsDeleted(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newJSONResponse(200, map[string]interface{}{
			"ok": true,
			"members": []map[string]interface{}{
				{"id": "U1", "name": "alice", "real_name": "Alice", "deleted": true},
			},
		}), nil
	})

	c := slackClientWithRT(rt)
	_, err := c.FindUserByName("alice")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found: @alice")
}

func TestFindUserByName_NotFound(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newJSONResponse(200, map[string]interface{}{
			"ok":      true,
			"members": []map[string]interface{}{},
		}), nil
	})

	c := slackClientWithRT(rt)
	_, err := c.FindUserByName("ghost")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found: @ghost")
}

func TestFindUserByName_APIError(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newJSONResponse(200, map[string]interface{}{
			"ok":    false,
			"error": "token_revoked",
		}), nil
	})

	c := slackClientWithRT(rt)
	_, err := c.FindUserByName("alice")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token_revoked")
}

func TestFindUserByName_HTTPFailure(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("network down")
	})

	c := slackClientWithRT(rt)
	_, err := c.FindUserByName("alice")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get users list")
}

// ---------- SendToChannels ----------

func TestSendToChannels_EmptyIDs(t *testing.T) {
	c := slackClientWithRT(nil)
	err := c.SendToChannels(nil, "msg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "channel IDs are required")
}

func TestSendToChannels_EmptyMessage(t *testing.T) {
	c := slackClientWithRT(nil)
	err := c.SendToChannels([]string{"C1"}, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "message is required")
}

func TestSendToChannels_AllSucceed(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newJSONResponse(200, map[string]interface{}{"ok": true}), nil
	})

	c := slackClientWithRT(rt)
	err := c.SendToChannels([]string{"C1", "C2"}, "broadcast")
	require.NoError(t, err)
}

func TestSendToChannels_AllFail(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("network error")
	})

	c := slackClientWithRT(rt)
	err := c.SendToChannels([]string{"C1", "C2"}, "msg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to send to any channel")
}

func TestSendToChannels_PartialFailure(t *testing.T) {
	call := 0
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		call++
		if call == 1 {
			return nil, fmt.Errorf("network error")
		}
		return newJSONResponse(200, map[string]interface{}{"ok": true}), nil
	})

	c := slackClientWithRT(rt)
	err := c.SendToChannels([]string{"C-fail", "C-ok"}, "msg")
	require.NoError(t, err) // partial success is OK
}
