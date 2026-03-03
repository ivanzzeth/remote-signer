package notify

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func telegramClientWithRT(rt http.RoundTripper) *TelegramClient {
	c, _ := NewTelegramClient("123:ABC")
	c.httpClient = &http.Client{Transport: rt}
	return c
}

func TestNewTelegramClient_EmptyToken(t *testing.T) {
	_, err := NewTelegramClient("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "telegram bot token is required")
}

func TestNewTelegramClient_Valid(t *testing.T) {
	c, err := NewTelegramClient("123:ABC")
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "123:ABC", c.botToken)
}

func TestTelegramClient_SendToChats_EmptyChatIDs(t *testing.T) {
	c := telegramClientWithRT(nil)
	err := c.SendToChats(nil, "msg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chat IDs are required")

	err = c.SendToChats([]string{}, "msg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chat IDs are required")
}

func TestTelegramClient_SendToChats_EmptyMessage(t *testing.T) {
	c := telegramClientWithRT(nil)
	err := c.SendToChats([]string{"-100123"}, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "message is required")
}

func TestTelegramClient_SendToChats_Success(t *testing.T) {
	var received sendMessageRequest
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Contains(t, req.URL.String(), "api.telegram.org")
		assert.Contains(t, req.URL.String(), "sendMessage")
		_ = json.NewDecoder(req.Body).Decode(&received)
		return newJSONResponse(200, sendMessageResponse{OK: true}), nil
	})

	c := telegramClientWithRT(rt)
	err := c.SendToChats([]string{"-1001234567890"}, "alert: test message")
	require.NoError(t, err)
	assert.Equal(t, "-1001234567890", received.ChatID)
	assert.Equal(t, "alert: test message", received.Text)
}

func TestTelegramClient_SendToChats_APIError(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newJSONResponse(200, sendMessageResponse{
			OK:          false,
			Description: "Bad Request: chat not found",
		}), nil
	})

	c := telegramClientWithRT(rt)
	err := c.SendToChats([]string{"-999"}, "msg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "telegram API error")
	assert.Contains(t, err.Error(), "chat not found")
}
