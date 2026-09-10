package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const telegramAPIBase = "https://api.telegram.org"

// TelegramClient sends messages via the Telegram Bot API.
type TelegramClient struct {
	botToken   string
	httpClient *http.Client
}

// NewTelegramClient creates a Telegram client with the given bot token.
func NewTelegramClient(botToken string) (*TelegramClient, error) {
	if botToken == "" {
		return nil, fmt.Errorf("telegram bot token is required")
	}

	return &TelegramClient{
		botToken: botToken,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// sendMessageRequest is the JSON body for sendMessage API.
type sendMessageRequest struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode,omitempty"` // "HTML" or "Markdown" to escape special chars in plain text
}

// sendMessageResponse is the API response.
type sendMessageResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description,omitempty"`
}

// telegramChats is the Telegram fan-out's half of the strings — see fanout.go.
var telegramChats = fanOutTarget{
	emptyErr:   "chat IDs are required",
	allFailed:  "failed to send to any Telegram chat",
	logField:   "chat_id",
	sendFailed: "Failed to send Telegram message",
	partial:    "Some Telegram chats failed to receive message",
	sent:       "Sent Telegram message",
	allSent:    "Successfully sent notification to Telegram chats",
}

// SendToChats sends the message to each chat (chat_id or @channel).
// chatID can be a numeric ID or a channel username (e.g. @mychannel).
// Partial failures are logged and tolerated; an error means nothing was
// delivered.
func (c *TelegramClient) SendToChats(chatIDs []string, message string) error {
	return fanOut(chatIDs, message, telegramChats, func(chatID string) error {
		return c.sendMessage(chatID, message)
	})
}

func (c *TelegramClient) sendMessage(chatID, text string) error {
	url := fmt.Sprintf("%s/bot%s/sendMessage", telegramAPIBase, c.botToken)

	payload := sendMessageRequest{
		ChatID: chatID,
		Text:   text,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to post message: %w", err)
	}
	defer resp.Body.Close()

	var result sendMessageResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if !result.OK {
		return fmt.Errorf("telegram API error: %s", result.Description)
	}

	return nil
}
