package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/logger"
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

// SendToChats sends the message to each chat (chat_id or @channel).
// chatID can be a numeric ID or a channel username (e.g. @mychannel).
func (c *TelegramClient) SendToChats(chatIDs []string, message string) error {
	if len(chatIDs) == 0 {
		return fmt.Errorf("chat IDs are required")
	}
	if message == "" {
		return fmt.Errorf("message is required")
	}

	log := logger.GetGlobal()
	var lastErr error
	successCount := 0

	for _, chatID := range chatIDs {
		if err := c.sendMessage(chatID, message); err != nil {
			lastErr = err
			log.Warn().
				Err(err).
				Str("chat_id", chatID).
				Msg("Failed to send Telegram message")
			continue
		}
		successCount++
		log.Debug().Str("chat_id", chatID).Msg("Sent Telegram message")
	}

	if successCount == 0 {
		return fmt.Errorf("failed to send to any Telegram chat: %w", lastErr)
	}
	if lastErr != nil {
		log.Warn().
			Int("success_count", successCount).
			Int("total_count", len(chatIDs)).
			Msg("Some Telegram chats failed to receive message")
	} else {
		log.Info().
			Int("chat_count", len(chatIDs)).
			Msg("Successfully sent notification to Telegram chats")
	}

	return nil
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
